use trufflescan::scan;
#[tokio::main]
async fn main() {
    scan().await.unwrap();
}
