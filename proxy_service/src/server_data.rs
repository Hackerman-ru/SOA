use jsonwebtoken::{Algorithm, DecodingKey};
use std::{fs::read, path::PathBuf};

pub struct ServerData {
    pub user_service_url: String,
    pub decoding_key: DecodingKey,
    pub algorithm: Algorithm,
}

impl ServerData {
    pub async fn new(user_service_url: String, public_path: PathBuf) -> Self {
        let public_key = read(public_path).unwrap();
        let decoding_key = DecodingKey::from_rsa_pem(&public_key).unwrap();

        Self {
            user_service_url,
            decoding_key,
            algorithm: Algorithm::RS256,
        }
    }
}
