use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use std::{fs::read, path::PathBuf};

pub struct Keys {
    pub decoding_key: DecodingKey,
    pub encoding_key: EncodingKey,
    pub algorithm: Algorithm,
}

impl Keys {
    pub async fn new(public_path: PathBuf, private_path: PathBuf) -> Self {
        let private_key = read(private_path).unwrap();
        let encoding_key = EncodingKey::from_rsa_pem(&private_key).unwrap();
        let public_key = read(public_path).unwrap();
        let decoding_key = DecodingKey::from_rsa_pem(&public_key).unwrap();

        Self {
            decoding_key,
            encoding_key,
            algorithm: Algorithm::RS256,
        }
    }
}

impl Default for Keys {
    fn default() -> Self {
        const SECRET_KEY: &str = "secret_key";

        Self {
            decoding_key: DecodingKey::from_secret(SECRET_KEY.as_ref()),
            encoding_key: EncodingKey::from_secret(SECRET_KEY.as_ref()),
            algorithm: Algorithm::HS256,
        }
    }
}
