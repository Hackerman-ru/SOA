mod clickhouse;
mod grpc;

use clap::Parser;
use clickhouse::ClickHouseClient;
use std::sync::Arc;

#[derive(Debug, Parser)]
#[command(author, version)]
#[command(about = "Reaction Service", long_about = None)]
pub struct Args {
    /// URL to Clickhouse
    #[arg(long)]
    clickhouse: String,
    /// Port to listen to
    #[arg(short, long)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let addr = ([0, 0, 0, 0], args.port).into();

    let clickhouse = Arc::new(ClickHouseClient::new(&args.clickhouse).await?);

    println!("Running reaction-service on {}", addr);

    grpc::run_server(addr, clickhouse).await
}
