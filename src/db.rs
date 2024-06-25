use std::sync::Arc;

use anyhow::anyhow;
use once_cell::sync::Lazy;

use crate::{config, errorln, outputln};

#[derive(Debug, Clone)]
pub struct DataChannelObject {
    pub endpoint_identifier: String,
    pub log_identifier: String,
    pub timestamp: i64,
    pub message: serde_json::Value,
}

static mut DATA_CHANNEL: Lazy<(tokio::sync::mpsc::Sender<DataChannelObject>, tokio::sync::mpsc::Receiver<DataChannelObject>)> = Lazy::new(||
    tokio::sync::mpsc::channel(4096)
);

pub async fn upload_log(data: &DataChannelObject) {
    let tx = unsafe { &mut DATA_CHANNEL.0 };
    let _ = tx.send(data.clone()).await;
}

#[derive(Debug, Clone)]
struct DangerousServerVerification;

impl DangerousServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(DangerousServerVerification {})
    }
}

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for DangerousServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        vec![
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA256,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

async fn construct_pg_config() -> tokio_postgres::Config {
    let config_data = {
        config::get_clone()
    };

    let mut pg_config = tokio_postgres::config::Config::new();

    pg_config.host(&config_data.db_remote_address);
    pg_config.port(config_data.db_remote_port);
    pg_config.dbname("route8");
    pg_config.user("route8-user");
    pg_config.password(&config_data.db_password);
    pg_config.ssl_mode(tokio_postgres::config::SslMode::Require);

    pg_config
}

async fn worker_thread() -> anyhow::Result<()> {
    let pg_config = construct_pg_config().await;
    let client_config = tokio_rustls::rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(DangerousServerVerification::new())
        .with_no_client_auth();

    let tls_connector = tokio_postgres_rustls::MakeRustlsConnect::new(client_config);

    let data_rx = unsafe { &mut DATA_CHANNEL.1 };
    let (connection_lost_tx, mut connection_lost_rx) = tokio::sync::mpsc::channel::<bool>(1);
    let (mut client, connection) = pg_config.connect(tls_connector).await?;

    outputln!("db", "connected");

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            errorln!("db", "lost connection due to error: {}", e.to_string());
            let _ = connection_lost_tx.send(true).await;
        }
    });

    tokio::select! {
        connection_lost_data = connection_lost_rx.recv() => {
            if connection_lost_data.is_some() {
                return Err(anyhow!("connection closed"));
            }
        }
        data = data_rx.recv() => {
            if let Some(data) = data {
                let transaction = client.transaction().await?;

                transaction.execute(r#"INSERT INTO tb_log (
                        endpoint_identifier,
                        log_identifier,
                        timestamp,
                        message
                    ) VALUES (
                        $1, $2, $3, $4
                    )"#,
                    &[&data.endpoint_identifier, &data.log_identifier, &data.timestamp, &data.message]).await?;

                transaction.commit().await?;
            }
        }
    }

    Ok(())
}

pub async fn initialize() -> anyhow::Result<()> {
    tokio::spawn(async move {
        loop {
            if let Err(e) = worker_thread().await {
                errorln!("db", "{}", e.to_string());
            }

            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    });

    Ok(())
}
