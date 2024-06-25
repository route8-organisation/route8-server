use anyhow::{anyhow, Context};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub mod debug;
pub mod config;
pub mod db;

static mut MAXIMUM_RECEIVE_SIZE: Option<usize> = None;
static mut STREAM_MTU: Option<usize> = None;

async fn stream_receive(stream: &mut tokio_native_tls::TlsStream<tokio::net::TcpStream>) -> anyhow::Result<String> {
    let maximum_receive_size = unsafe {
        MAXIMUM_RECEIVE_SIZE.expect("config is not initialized")
    };

    let mtu = unsafe {
        STREAM_MTU.expect("config is not initialized")
    };

    let mut buffer_blob: String = String::new();
    let mut buffer= vec![0 as u8; mtu];

    loop {
        let rx_size = stream.read(&mut buffer).await.map_err(|e| anyhow!("failed to receive due to {}", e.to_string()))?;

        if rx_size == 0 {
            return Err(anyhow!("stream closed"));
        }

        if buffer_blob.len() + rx_size >= maximum_receive_size {
            return Err(anyhow!("maximum packet size reached"));
        }

        match buffer.iter().position(|&v| v == 0) {
            Some(eof) => {
                buffer_blob.push_str(&String::from_utf8_lossy(&buffer[..eof]));
                break;
            },
            None => {
                buffer_blob.push_str(&String::from_utf8_lossy(&buffer));
            }
        }
    }

    Ok(buffer_blob)
}

async fn stream_write(stream: &mut tokio_native_tls::TlsStream<tokio::net::TcpStream>, data: String) -> anyhow::Result<()> {
    let mtu = unsafe {
        STREAM_MTU.expect("config is not initialized")
    };

    let mut buffer_blob = Vec::from(data);
    let mut index = 0 as usize;

    buffer_blob.push(0); // zero termination

    loop {
        let buffer_blob_len = buffer_blob.len();

        let packet_size = {
            if index + mtu >= buffer_blob_len {
                buffer_blob.len() - index
            } else {
                mtu
            }
        };

        stream.write(&buffer_blob[index..(index + packet_size)]).await.map_err(|e| anyhow!("failed to send due to {}", e.to_string()))?;
        index = index + packet_size;

        if index + packet_size >= buffer_blob_len {
            return Ok(())
        }
    }
}

async fn client_authentication(stream: &mut tokio_native_tls::TlsStream<tokio::net::TcpStream>, connaddr: &String) -> anyhow::Result<String> {
    let packet = stream_receive(stream).await?;
    let json_packet: serde_json::Value = serde_json::from_str(&packet).context("invalid json packet")?;

    let field_command = json_packet["command"].as_str().context("missing 'command' field")?;
    let field_data = json_packet.get("data").context("missing 'data' field")?;
    let field_identity = json_packet["identity"].as_str().context("missing 'identity' field")?;
    let field_password = field_data["password"].as_str().context("missing 'data.password' field")?;

    if field_command != "auth" {
        return Err(anyhow!("failed to authenticate due to invalid packet"));
    }

    if field_identity == "foobar" && field_password == "foobar" {
        let _ = stream_write(stream, serde_json::json!({
            "auth": "authenticated"
        }).to_string()).await?;

        accessln!(connaddr, "client authenticated");

        return Ok(field_identity.to_owned());
    } else {
        let _ = stream_write(stream, serde_json::json!({
            "auth": "unathorized"
        }).to_string()).await;

        return Err(anyhow!("invalid credentials"))
    }
}

async fn client_procedure(mut stream: tokio_native_tls::TlsStream<tokio::net::TcpStream>, connaddr: &String) -> anyhow::Result<()> {
    let endpoint_identifier = client_authentication(&mut stream, connaddr).await.map_err(|e| anyhow!("failed to authenticate due to {}", e.to_string()))?;

    loop {
        let recv_data: serde_json::Value = serde_json::from_str(&stream_receive(&mut stream).await.map_err(|e| anyhow!("failed to receive due to {}", e.to_string()))?)?;

        let field_command = recv_data["command"].as_str().context("missing 'command' field")?;
        let field_data = recv_data.get("data").context("missing 'data' field")?;

        if field_command == "log" {
            let field_data_identifier = field_data["identifier"].as_str().context("missing 'data.identifier' field")?;
            let field_data_timestamp = field_data["timestamp"].as_i64().context("missing 'data.timestamp' field")?;
            let field_data_message = field_data.get("message").context("missing 'data.message' field")?;

            db::upload_log(&db::DataChannelObject {
                endpoint_identifier: endpoint_identifier.clone(),
                log_identifier: field_data_identifier.to_owned(),
                timestamp: field_data_timestamp,
                message: field_data_message.clone()
            }).await;
        }
    }
}

async fn server() -> anyhow::Result<()> {
    let config_clone = {
        config::get_clone()
    };

    let server_cert = std::fs::read(config_clone.tls_certifcate).map_err(|e| anyhow!("failed to loat TLS certificate, error: {}", e.to_string()))?;
    let server_key = std::fs::read(config_clone.tls_private_key).map_err(|e| anyhow!("failed to loat TLS key, error: {}", e.to_string()))?;
    let tls_acceptor = native_tls::TlsAcceptor::builder(native_tls::Identity::from_pkcs8(&server_cert, &server_key)?).build().map_err(|e| anyhow!("invalid TLS certiifcate or key, error: {}", e.to_string()))?;
    let tls_acceptor = tokio_native_tls::TlsAcceptor::from(tls_acceptor);
    let listen_address = format!("{}:{}", config_clone.listen_address, config_clone.listen_port);
    let listener = tokio::net::TcpListener::bind(&listen_address).await.map_err(|e| anyhow!("failed to listen on '{}', error: {}", listen_address, e.to_string()))?;

    outputln!("server", "listening on {listen_address}");

    loop {
        let tls_acceptor = tls_acceptor.clone();
        let (stream, connaddr) = listener.accept().await.map_err(|e| anyhow!("failed to accept a client, error: {}", e.to_string()))?;

        tokio::spawn(async move {
            let connaddr = connaddr.to_string();

            match tls_acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    accessln!(connaddr, "stream established");

                    if let Err(e) = client_procedure(tls_stream, &connaddr).await {
                        errorln!(connaddr, "{}", e.to_string());
                    }

                    accessln!(connaddr, "stream closed");
                },
                Err(e) => errorln!(connaddr, "TLS acceptance failure, error: {}", e.to_string())
            }
        });
    }
}

fn initialize_global_variables() {
    let config_clone = config::get_clone();

    unsafe {
        MAXIMUM_RECEIVE_SIZE = Some(config_clone.maximum_receive_size);
        STREAM_MTU = Some(config_clone.mtu);
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = debug::initialize() {
        eprintln!("failed to initialize the debug module due to {}", e.to_string());
        return;
    }

    outputln!("app", "############## STARTED ##############");

    if let Err(e) = config::initialize() {
        errorln!("app", "failed to load the config due to {}", e.to_string());
        return;
    }

    initialize_global_variables();

    if let Err(e) = db::initialize().await {
        errorln!("db", "failed to initialize due to {}", e.to_string());
        return;
    }

    if let Err(e) = server().await {
        errorln!("server", "server error: {}", e.to_string());
    }
}
