use std::path::PathBuf;

use actix_web::{App, HttpServer, web};
use clap::Parser;
use db::get_db_pool;
use rdkafka::{ClientConfig, producer::FutureProducer};
use server_data::Keys;

mod db;
mod handlers;
mod models;
mod routes;
mod server_data;

#[derive(Debug, Parser)]
#[command(author, version)]
#[command(about = "Authentication Service", long_about = None)]
pub struct Args {
    /// Path to public key
    #[arg(short, long)]
    public: PathBuf,
    /// Path to private key
    #[arg(short, long)]
    private: PathBuf,
    /// URL to kafka
    #[arg(long)]
    kafka: String,
    /// Port to listen to
    #[arg(short, long)]
    port: u16,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let db_pool = web::Data::new(get_db_pool().await);
    let kafka_producer: FutureProducer = ClientConfig::new()
        .set("bootstrap.servers", &args.kafka)
        .create()
        .unwrap();
    let kafka_producer = web::Data::new(kafka_producer);
    let keys = web::Data::new(Keys::new(args.public, args.private).await);

    println!("Running user-service on 0.0.0.0:{}", args.port);

    HttpServer::new(move || {
        App::new()
            .app_data(kafka_producer.clone())
            .app_data(db_pool.clone())
            .app_data(keys.clone())
            .configure(routes::init_routes)
    })
    .bind(("0.0.0.0", args.port))?
    .run()
    .await
}
