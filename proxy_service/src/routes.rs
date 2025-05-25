use crate::{
    handlers::{
        comment_post, create_post, delete_post, get_comment_dynamics, get_comments,
        get_like_dynamics, get_post, get_post_stats, get_top_creators, get_top_posts,
        get_view_dynamics, like_post, list_posts, update_post, view_post,
    },
    server_data::ServerData,
};
use actix_web::{Error, HttpRequest, HttpResponse, web};
use awc::Client;
use serde_json::json;

async fn proxy_user_service(
    server_data: web::Data<ServerData>,
    req: HttpRequest,
    body: web::Bytes,
    tail: web::Path<String>,
) -> Result<HttpResponse, Error> {
    let client = Client::default();

    let target_path = format!("/api/v1/{}", tail);

    let target_url = format!("{}{}", server_data.user_service_url, target_path);

    let mut proxy_request = client.request_from(&target_url, req.head());

    for (name, value) in req.headers() {
        proxy_request = proxy_request.insert_header((name.clone(), value.clone()));
    }

    let mut response = match proxy_request.send_body(body).await {
        Ok(res) => res,
        Err(e) => {
            return Ok(HttpResponse::InternalServerError().json(json!({"error":e.to_string()})));
        }
    };

    let mut client_resp = HttpResponse::build(response.status());
    for (name, value) in response.headers().iter() {
        client_resp.insert_header((name.clone(), value.clone()));
    }

    Ok(client_resp.body(response.body().await?))
}

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .service(web::resource("/user/{tail:.*}").to(proxy_user_service))
            .service(
                web::scope("/post")
                    .route("/create", web::post().to(create_post))
                    .route("/update", web::put().to(update_post))
                    .route("/get", web::get().to(get_post))
                    .route("/delete", web::delete().to(delete_post))
                    .route("/list", web::get().to(list_posts))
                    .route("/comment", web::post().to(comment_post))
                    .route("/comments", web::get().to(get_comments))
                    .route("/like", web::post().to(like_post))
                    .route("/view", web::post().to(view_post)),
            )
            .service(
                web::scope("/reaction")
                    .route("/stats", web::get().to(get_post_stats))
                    .route("/views_dynamic", web::get().to(get_view_dynamics))
                    .route("/likes_dynamic", web::get().to(get_like_dynamics))
                    .route("/comments_dynamic", web::get().to(get_comment_dynamics))
                    .route("/top_posts", web::get().to(get_top_posts))
                    .route("/top_creators", web::get().to(get_top_creators)),
            ),
    );
}
