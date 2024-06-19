pub mod debug;
pub mod config;

#[tokio::main]
async fn main() {
    if let Err(e) = debug::initialize() {
        eprintln!("failed to initialize the debug module due to {}", e.to_string());
        return;
    }

    outputln!("app", "############## STARTED ##############");
    accessln!("app", "############## STARTED ##############");

    if let Err(e) = config::initialize() {
        errorln!("app", "failed to load the config due to {}", e.to_string());
        return;
    }
}
