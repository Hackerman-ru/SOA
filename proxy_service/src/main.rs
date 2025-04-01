use std::path::PathBuf;

use actix_web::{App, HttpServer, web};
use clap::Parser;
use post_service::PostService;
use server_data::ServerData;

mod handlers;
mod post_service;
mod posts {
    include!("posts.rs");
}
mod routes;
mod server_data;

#[derive(Debug, Parser)]
#[command(author, version)]
#[command(about = "Proxy Service", long_about = None)]
pub struct Args {
    /// URL to post-service
    #[arg(long)]
    post: String,
    /// URL to user-service
    #[arg(long)]
    user: String,
    /// Path to public key
    #[arg(long)]
    public: PathBuf,
    /// Port to listen to
    #[arg(long)]
    port: u16,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let post_service = web::Data::new(PostService::new(args.post).await.unwrap());
    let server_data = web::Data::new(ServerData::new(args.user, args.public).await);

    println!("Running proxy-service on 0.0.0.0:{}", args.port);

    HttpServer::new(move || {
        App::new()
            .app_data(post_service.clone())
            .app_data(server_data.clone())
            .configure(routes::init_routes)
    })
    .bind(("0.0.0.0", args.port))?
    .run()
    .await
}
