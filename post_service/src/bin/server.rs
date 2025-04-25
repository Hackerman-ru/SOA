use clap::Parser;
use post_service_lib::{create_server, CassandraSession, RdKafkaProducer};
use tonic::transport::Server;

#[derive(Debug, Parser)]
#[command(author, version)]
#[command(about = "Post Service", long_about = None)]
pub struct Args {
    /// URL to Cassandra
    #[arg(long)]
    cassandra: String,
    /// URL to kafka
    #[arg(long)]
    kafka: String,
    /// Port to listen to
    #[arg(short, long)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let addr = ([0, 0, 0, 0], args.port).into();

    let cassandra = CassandraSession::new(&[&args.cassandra]).await?;
    let kafka_producer = RdKafkaProducer::new(&args.kafka)?;
    let post_service = create_server(cassandra, kafka_producer).await?;

    println!("Running post-service on {}", addr);

    Server::builder()
        .add_service(post_service)
        .serve(addr)
        .await?;

    Ok(())
}
