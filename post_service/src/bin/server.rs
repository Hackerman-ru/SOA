use std::env;

use clap::Parser;
use dotenv::dotenv;
use post_service_lib::{create_server, CassandraSession};
use tonic::transport::Server;

#[derive(Debug, Parser)]
#[command(author, version)]
#[command(about = "Post Service", long_about = None)]
pub struct Args {
    /// Port to listen to
    #[arg(short, long)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    let args = Args::parse();
    let addr = ([0, 0, 0, 0], args.port).into();

    let node_address = env::var("NODE_ADDRESS").expect("NODE_ADDRESS must be set");
    let cassandra = CassandraSession::new(&[&node_address]).await?;

    let post_service = create_server(cassandra).await?;

    println!("Running post-service on {}", addr);

    Server::builder()
        .add_service(post_service)
        .serve(addr)
        .await?;

    Ok(())
}
