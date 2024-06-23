use std::fs;

const FILENAME: &str = "config.yml";

static mut CONFIG_DATA: Option<Config> = None;

#[derive(serde::Deserialize, serde::Serialize, Clone)]
pub struct Config {
    pub listen_address: String,
    pub listen_port: u16,
    pub tls_certifcate: String,
    pub tls_private_key: String
}

pub fn get_clone() -> Config {
    let config = unsafe {
        CONFIG_DATA.clone().expect("config is not initialized")
    };

    config
}

pub fn initialize() -> anyhow::Result<()> {
    let file_content = fs::read_to_string(FILENAME)?;
    let data: Config = serde_json::from_str(&file_content)?;

    unsafe {
        CONFIG_DATA = Some(data);
    }

    Ok(())
}
