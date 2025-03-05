use crate::handlers::{get_my_profile, get_profile, login, logout, register, update_my_profile};
use actix_web::web;

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .route("/register", web::post().to(register))
            .route("/login", web::post().to(login))
            .route("/logout", web::post().to(logout))
            .route("/profile/my", web::put().to(update_my_profile))
            .route("/profile/my", web::put().to(get_my_profile))
            .route("/profile/{user_id}", web::get().to(get_profile)),
    );
}
