use trufflescan::connect;
#[tokio::main]
async fn main() {
    connect().await.unwrap();
}
