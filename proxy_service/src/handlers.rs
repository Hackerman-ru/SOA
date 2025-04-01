// src/handlers/post_handlers.rs
use crate::post_service::PostService;
use crate::{posts::*, server_data::ServerData};
use actix_web::{HttpRequest, HttpResponse, Responder, web};
use jsonwebtoken::{Validation, decode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tonic::{Code, Status};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // UUID в виде строки
    exp: usize,  // expiration time
}

fn extract_jwt_from_cookie(req: &HttpRequest) -> Result<String, HttpResponse> {
    req.cookie("jwt")
        .map(|cookie| cookie.value().to_string())
        .ok_or(HttpResponse::Unauthorized().json(json!({ "proxy-service/error": "Missing token" })))
}

fn validate_jwt(token: &String, server_data: &web::Data<ServerData>) -> Result<Uuid, HttpResponse> {
    let token_data = decode::<Claims>(
        &token,
        &server_data.decoding_key,
        &Validation::new(server_data.algorithm),
    )
    .map_err(|_| {
        HttpResponse::Unauthorized().json(json!({ "proxy-service/error": "Invalid token" }))
    })?;

    Uuid::parse_str(&token_data.claims.sub).map_err(|_| {
        HttpResponse::Unauthorized().json(json!({ "proxy-service/error": "Invalid UUID in token" }))
    })
}

fn check_jwt(
    user_id: Uuid,
    server_data: &web::Data<ServerData>,
    req: &HttpRequest,
) -> Result<(), HttpResponse> {
    let token = match extract_jwt_from_cookie(&req) {
        Ok(token) => token,
        Err(response) => return Err(response),
    };
    let id = match validate_jwt(&token, &server_data) {
        Ok(id) => id,
        Err(response) => return Err(response),
    };
    if id != user_id {
        return Err(HttpResponse::Forbidden()
            .json(json!({"proxy-service/error": "Creator or user id in request doesn't match your user_id"})));
    }
    Ok(())
}

fn convert_err(status: Status) -> HttpResponse {
    match status.code() {
        Code::NotFound => HttpResponse::NotFound().json(json!({ "error": status.message() })),
        Code::PermissionDenied => {
            HttpResponse::Forbidden().json(json!({ "error": status.message() }))
        }
        Code::InvalidArgument => {
            HttpResponse::BadRequest().json(json!({ "error": status.message() }))
        }
        _ => HttpResponse::InternalServerError().json(json!({ "error": status.message() })),
    }
}

pub async fn create_post(
    post_service: web::Data<PostService>,
    server_data: web::Data<ServerData>,
    input: web::Json<CreatePostRequest>,
    req: HttpRequest,
) -> impl Responder {
    let request = input.0;
    let creator_id = match Uuid::parse_str(&request.creator_id) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(json!({ "proxy-service/error": "Invalid UUID in creator_id" }));
        }
    };
    if let Err(response) = check_jwt(creator_id, &server_data, &req) {
        return response;
    }
    let mut client = post_service.get_ref().clone();

    let response = client.create_post(request).await;
    match response {
        Ok(response) => HttpResponse::Ok().json(response.post),
        Err(status) => convert_err(status),
    }
}

pub async fn update_post(
    post_service: web::Data<PostService>,
    server_data: web::Data<ServerData>,
    input: web::Json<UpdatePostRequest>,
    req: HttpRequest,
) -> impl Responder {
    let request = input.0;
    let user_id = match Uuid::parse_str(&request.user_id) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(json!({ "proxy-service/error": "Invalid UUID in user_id" }));
        }
    };
    if let Err(response) = check_jwt(user_id, &server_data, &req) {
        return response;
    }
    let mut client = post_service.get_ref().clone();

    let response = client.update_post(request).await;
    match response {
        Ok(response) => HttpResponse::Ok().json(response.post),
        Err(status) => convert_err(status),
    }
}

pub async fn get_post(
    post_service: web::Data<PostService>,
    server_data: web::Data<ServerData>,
    input: web::Json<GetPostRequest>,
    req: HttpRequest,
) -> impl Responder {
    let request = input.0;
    let user_id = match Uuid::parse_str(&request.user_id) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(json!({ "proxy-service/error": "Invalid UUID in user_id" }));
        }
    };
    if let Err(response) = check_jwt(user_id, &server_data, &req) {
        return response;
    }
    let mut client = post_service.get_ref().clone();

    let response = client.get_post(request).await;
    match response {
        Ok(response) => HttpResponse::Ok().json(response.post),
        Err(status) => convert_err(status),
    }
}

pub async fn delete_post(
    post_service: web::Data<PostService>,
    server_data: web::Data<ServerData>,
    input: web::Json<DeletePostRequest>,
    req: HttpRequest,
) -> impl Responder {
    let request = input.0;
    let user_id = match Uuid::parse_str(&request.user_id) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(json!({ "proxy-service/error": "Invalid UUID in user_id" }));
        }
    };
    if let Err(response) = check_jwt(user_id, &server_data, &req) {
        return response;
    }
    let mut client = post_service.get_ref().clone();

    let response = client.delete_post(request).await;
    match response {
        Ok(response) => HttpResponse::Ok().json(json!({ "success": response.success })),
        Err(status) => convert_err(status),
    }
}

pub async fn list_posts(
    post_service: web::Data<PostService>,
    server_data: web::Data<ServerData>,
    input: web::Json<ListPostsRequest>,
    req: HttpRequest,
) -> impl Responder {
    let request = input.0;
    let user_id = match Uuid::parse_str(&request.user_id) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(json!({ "proxy-service/error": "Invalid UUID in user_id" }));
        }
    };
    if let Err(response) = check_jwt(user_id, &server_data, &req) {
        return response;
    }
    let mut client = post_service.get_ref().clone();

    let response = client.list_posts(request).await;
    match response {
        Ok(response) => HttpResponse::Ok().json(json!({
            "posts": response.posts,
            "next_page_token": response.next_page_token
        })),
        Err(status) => convert_err(status),
    }
}
