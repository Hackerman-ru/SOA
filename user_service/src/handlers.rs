use std::time::Duration;

use crate::{
    models::{LoginData, RegisterData, UserResponse, UserUpdateRequest},
    server_data::Keys,
};
use actix_web::{
    HttpRequest, HttpResponse, Responder,
    cookie::{self, Cookie, SameSite},
    web,
};
use bcrypt::{DEFAULT_COST, hash, verify};
use rdkafka::producer::{FutureProducer, FutureRecord};
use serde_json::json;
use sqlx::PgPool;

use chrono::{NaiveDateTime, Utc};
use jsonwebtoken::{Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use async_trait::async_trait;
use rdkafka::error::KafkaError;

#[async_trait]
pub trait KafkaProducer: Send + Sync {
    async fn send_register_event(
        &self,
        user_id: Uuid,
        created_at: NaiveDateTime,
    ) -> Result<(), KafkaError>;
}

#[async_trait]
impl KafkaProducer for FutureProducer {
    async fn send_register_event(
        &self,
        user_id: Uuid,
        created_at: NaiveDateTime,
    ) -> Result<(), KafkaError> {
        let payload = json!({
            "user_id": user_id,
            "timestamp": created_at,
        });

        let key_str = user_id.to_string();
        let payload_str = payload.to_string();
        let record = FutureRecord::to("register")
            .payload(&payload_str)
            .key(&key_str);

        self.send(record, Duration::from_secs(3))
            .await
            .map(|_| ())
            .map_err(|(e, _)| e)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // UUID в виде строки
    exp: usize,  // expiration time
}

fn create_jwt(id: Uuid, keys: &Keys) -> Result<String, jsonwebtoken::errors::Error> {
    let header = Header::new(keys.algorithm);

    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::hours(24))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: id.to_string(),
        exp: expiration as usize,
    };

    encode(&header, &claims, &keys.encoding_key)
}

fn extract_jwt_from_cookie(req: &HttpRequest) -> Result<String, HttpResponse> {
    req.cookie("jwt")
        .map(|cookie| cookie.value().to_string())
        .ok_or(HttpResponse::Unauthorized().json(json!({ "error": "Missing token" })))
}

fn validate_jwt(token: &String, keys: &Keys) -> Result<Uuid, HttpResponse> {
    let token_data = decode::<Claims>(&token, &keys.decoding_key, &Validation::new(keys.algorithm))
        .map_err(|_| HttpResponse::Unauthorized().json(json!({ "error": "Invalid token" })))?;

    Uuid::parse_str(&token_data.claims.sub)
        .map_err(|_| HttpResponse::Unauthorized().json(json!({ "error": "Invalid UUID in token" })))
}

pub async fn register(
    kafka_producer: web::Data<dyn KafkaProducer>,
    register_data: web::Json<RegisterData>,
    db_pool: web::Data<PgPool>,
) -> impl Responder {
    let password_hash = hash(register_data.password.clone(), DEFAULT_COST).unwrap();
    let insert_result = sqlx::query!(
        "INSERT INTO users (username, password_hash, email) VALUES ($1, $2, $3) RETURNING id, created_at",
        register_data.username,
        password_hash,
        register_data.email
    )
    .fetch_one(&**db_pool)
    .await;

    match insert_result {
        Ok(record) => {
            match kafka_producer
                .send_register_event(record.id, record.created_at)
                .await
            {
                Ok(_) => HttpResponse::Ok()
                    .json(json!({ "message": "User registered successfully", "id": record.id })),
                Err(e) => {
                    HttpResponse::InternalServerError().json(json!({ "error": e.to_string() }))
                }
            }
        }
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => HttpResponse::Conflict()
            .json(json!({"error": "User with such username or email already exists"})),
        Err(e) => {
            eprintln!("Failed to register user: {:?}", e);
            HttpResponse::InternalServerError().json(json!({ "error": "Failed to register user" }))
        }
    }
}

pub async fn login(
    login_data: web::Json<LoginData>,
    keys: web::Data<Keys>,
    db_pool: web::Data<PgPool>,
) -> impl Responder {
    let select_result = sqlx::query!(
        "SELECT id, password_hash FROM users WHERE username = $1",
        login_data.username
    )
    .fetch_one(&**db_pool)
    .await;

    match select_result {
        Ok(user) => {
            if !verify(login_data.password.clone(), &user.password_hash).unwrap() {
                HttpResponse::Unauthorized().json(json!({ "error": "Invalid credentials" }))
            } else {
                let token = create_jwt(user.id, &keys).unwrap();

                let cookie = Cookie::build("jwt", token)
                    .path("/")
                    .http_only(true)
                    .same_site(SameSite::Strict)
                    .max_age(cookie::time::Duration::hours(24))
                    .finish();

                HttpResponse::Ok()
                    .cookie(cookie)
                    .json(json!({ "message": "Login successful", "id": user.id }))
            }
        }
        Err(sqlx::Error::RowNotFound) => {
            HttpResponse::NotFound().json(json!({ "error": "User not found" }))
        }
        Err(e) => {
            eprintln!("Failed to login user: {:?}", e);
            HttpResponse::InternalServerError().json(json!({ "error": "Database error" }))
        }
    }
}

pub async fn logout() -> impl Responder {
    let cookie = Cookie::build("jwt", "")
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(cookie::SameSite::Strict)
        .max_age(cookie::time::Duration::seconds(0))
        .finish();

    HttpResponse::Ok()
        .cookie(cookie)
        .json(json!({ "message": "Logout successful" }))
}

pub async fn update_my_profile(
    req: HttpRequest,
    update_data: web::Json<UserUpdateRequest>,
    keys: web::Data<Keys>,
    db_pool: web::Data<PgPool>,
) -> impl Responder {
    let token = match extract_jwt_from_cookie(&req) {
        Ok(token) => token,
        Err(response) => return response,
    };
    let id = match validate_jwt(&token, &keys) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let update_result = sqlx::query_as!(UserResponse,
        r#"
        UPDATE users
        SET email = COALESCE($1, email),
            first_name = COALESCE($2, first_name),
            last_name = COALESCE($3, last_name),
            date_of_birth = COALESCE($4, date_of_birth),
            phone_number = COALESCE($5, phone_number),
            created_at = created_at,
            updated_at = $6
        WHERE id = $7
        RETURNING id, username, email, first_name, last_name, date_of_birth, phone_number, created_at, updated_at
        "#,
        update_data.email,
        update_data.first_name,
        update_data.last_name,
        update_data.date_of_birth,
        update_data.phone_number,
        Utc::now().naive_utc(),
        id,
    )
    .fetch_one(&**db_pool)
    .await;

    match update_result {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(e) => {
            eprintln!("Failed to update user profile: {:?}", e);
            HttpResponse::InternalServerError().json(json!({ "error": "Failed to update profile" }))
        }
    }
}

pub async fn get_profile(user_id: web::Path<Uuid>, db_pool: web::Data<PgPool>) -> impl Responder {
    let select_result = sqlx::query_as!(
        UserResponse,
        r#"
        SELECT id, username, email, first_name, last_name, date_of_birth, phone_number, created_at, updated_at
        FROM users
        WHERE id = $1
        "#,
        user_id.into_inner()
    )
    .fetch_one(&**db_pool)
    .await;

    match select_result {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(sqlx::Error::RowNotFound) => {
            HttpResponse::NotFound().json(json!({ "error": "User not found" }))
        }
        Err(e) => {
            eprintln!("Failed to fetch user profile: {:?}", e);
            HttpResponse::InternalServerError().json(json!({ "error": "Failed to fetch profile" }))
        }
    }
}

pub async fn get_my_profile(
    req: HttpRequest,
    keys: web::Data<Keys>,
    db_pool: web::Data<PgPool>,
) -> impl Responder {
    let token = match extract_jwt_from_cookie(&req) {
        Ok(token) => token,
        Err(response) => return response,
    };
    let id = match validate_jwt(&token, &keys) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let select_result = sqlx::query_as!(
        UserResponse,
        r#"
        SELECT id, username, email, first_name, last_name, date_of_birth, phone_number, created_at, updated_at
        FROM users
        WHERE id = $1
        "#,
        id
    )
    .fetch_one(&**db_pool)
    .await;

    match select_result {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(sqlx::Error::RowNotFound) => {
            HttpResponse::NotFound().json(json!({ "error": "User not found" }))
        }
        Err(e) => {
            eprintln!("Failed to fetch user profile: {:?}", e);
            HttpResponse::InternalServerError().json(json!({ "error": "Failed to fetch profile" }))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::db::{apply_migrations, clear_tables};

    use super::*;
    use actix_web::{App, test, web};
    use chrono::NaiveDate;
    use dotenv::dotenv;
    use lazy_static::lazy_static;
    use mockall::predicate::*;
    use mockall::*;
    use sqlx::{PgPool, Pool, Postgres};
    use std::env;
    use std::sync::{Arc, Mutex};

    mock! {
        pub KafkaProducerImpl {}
        #[async_trait]
        impl KafkaProducer for KafkaProducerImpl {
            async fn send_register_event(
                &self,
                user_id: Uuid,
                created_at: NaiveDateTime,
            ) -> Result<(), KafkaError>;
        }
    }

    lazy_static! {
        static ref TEST_MUTEX: Mutex<()> = Mutex::new(());
    }

    async fn prepare_pool() -> (Pool<Postgres>, MockKafkaProducerImpl) {
        dotenv().ok();
        let database_url = env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set");
        let pool = PgPool::connect(&database_url).await.unwrap();

        apply_migrations(&pool)
            .await
            .expect("Failed to apply migrations");
        clear_tables(&pool).await;
        let mock_producer = MockKafkaProducerImpl::new();

        (pool, mock_producer)
    }

    #[actix_web::test]
    async fn test_register_success() {
        let _guard = TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (pool, mut mock_producer) = prepare_pool().await;

        mock_producer
            .expect_send_register_event()
            .times(1)
            .returning(|_, _| Ok(()));

        let kafka: Arc<dyn KafkaProducer> = Arc::new(mock_producer);

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .app_data(web::Data::from(kafka))
                .route("/register", web::post().to(register)),
        )
        .await;

        let register_data = RegisterData {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            email: "test@example.com".to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/register")
            .set_json(&register_data)
            .to_request();

        let resp = test::call_service(&app, req).await;
        println!("{:?}", test::read_body(resp).await);
    }

    #[actix_web::test]
    async fn test_register_conflict() {
        let _guard = TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (pool, mut mock_producer) = prepare_pool().await;

        mock_producer
            .expect_send_register_event()
            .times(1)
            .returning(|_, _| Ok(()));

        let kafka: Arc<dyn KafkaProducer> = Arc::new(mock_producer);

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .app_data(web::Data::from(kafka))
                .route("/register", web::post().to(register)),
        )
        .await;

        let register_data = RegisterData {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            email: "test@example.com".to_string(),
        };

        // Первая регистрация
        let req = test::TestRequest::post()
            .uri("/register")
            .set_json(&register_data)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        // Вторая регистрация с теми же данными
        let req = test::TestRequest::post()
            .uri("/register")
            .set_json(&register_data)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 409);
    }

    #[actix_web::test]
    async fn test_login_success() {
        let _guard = TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (pool, _) = prepare_pool().await;

        // Регистрация пользователя для теста
        let register_data = RegisterData {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            email: "test@example.com".to_string(),
        };
        let password_hash = hash(register_data.password.clone(), DEFAULT_COST).unwrap();
        sqlx::query!(
            "INSERT INTO users (username, password_hash, email) VALUES ($1, $2, $3)",
            register_data.username,
            password_hash,
            register_data.email
        )
        .execute(&pool)
        .await
        .unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .app_data(web::Data::new(Keys::default()))
                .route("/login", web::post().to(login)),
        )
        .await;

        let login_data = LoginData {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/login")
            .set_json(&login_data)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn test_login_invalid_credentials() {
        let _guard = TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (pool, _) = prepare_pool().await;

        let register_data = RegisterData {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            email: "test@example.com".to_string(),
        };
        let password_hash = hash(register_data.password.clone(), DEFAULT_COST).unwrap();
        sqlx::query!(
            "INSERT INTO users (username, password_hash, email) VALUES ($1, $2, $3)",
            register_data.username,
            password_hash,
            register_data.email
        )
        .execute(&pool)
        .await
        .unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .app_data(web::Data::new(Keys::default()))
                .route("/login", web::post().to(login)),
        )
        .await;

        let login_data = LoginData {
            username: "testuser".to_string(),
            password: "wrongpass".to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/login")
            .set_json(&login_data)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_web::test]
    async fn test_logout_success() {
        let app = test::init_service(App::new().route("/logout", web::post().to(logout))).await;

        let req = test::TestRequest::post().uri("/logout").to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let cookies = resp.headers().get("Set-Cookie").unwrap().to_str().unwrap();
        assert!(cookies.contains("jwt=;"));
    }

    #[actix_web::test]
    async fn test_update_profile_success() {
        let _guard = TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (pool, _) = prepare_pool().await;

        // Регистрация пользователя для теста
        let register_data = RegisterData {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            email: "test@example.com".to_string(),
        };
        let password_hash = hash(register_data.password.clone(), DEFAULT_COST).unwrap();
        let result = sqlx::query!(
            "INSERT INTO users (username, password_hash, email) VALUES ($1, $2, $3) RETURNING id",
            register_data.username,
            password_hash,
            register_data.email
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .app_data(web::Data::new(Keys::default()))
                .route("/profile/me", web::put().to(update_my_profile)),
        )
        .await;

        let update_data = UserUpdateRequest {
            email: Some("new@example.com".to_string()),
            first_name: Some("New".to_string()),
            last_name: Some("User".to_string()),
            date_of_birth: NaiveDate::from_ymd_opt(1990, 01, 01),
            phone_number: Some("1234567890".to_string()),
        };

        let token = create_jwt(result.id, &Keys::default()).unwrap();
        let req = test::TestRequest::put()
            .uri("/profile/me")
            .cookie(Cookie::new("jwt", token))
            .set_json(&update_data)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn test_get_profile_success() {
        let _guard = TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (pool, _) = prepare_pool().await;

        let register_data = RegisterData {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            email: "test@example.com".to_string(),
        };
        let password_hash = hash(register_data.password.clone(), DEFAULT_COST).unwrap();
        let user_id = sqlx::query!(
            "INSERT INTO users (username, password_hash, email) VALUES ($1, $2, $3) RETURNING id",
            register_data.username,
            password_hash,
            register_data.email
        )
        .fetch_one(&pool)
        .await
        .unwrap()
        .id;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .route("/profile/{user_id}", web::get().to(get_profile)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri(&format!("/profile/{}", user_id))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["id"], user_id.to_string());
        assert_eq!(body["username"], "testuser");
    }

    #[actix_web::test]
    async fn test_get_my_profile_unauthorized() {
        let _guard = TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (pool, _) = prepare_pool().await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .app_data(web::Data::new(Keys::default()))
                .route("/profile/me", web::get().to(get_my_profile)),
        )
        .await;

        // Request without JWT cookie
        let req = test::TestRequest::get().uri("/profile/me").to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_web::test]
    async fn test_invalid_uuid_handling() {
        let _guard = TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (pool, _) = prepare_pool().await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .route("/profile/{user_id}", web::get().to(get_profile)),
        )
        .await;

        // Request with invalid UUID format
        let req = test::TestRequest::get()
            .uri("/profile/not-a-uuid")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404);
    }
}
