use crate::jwt_model;

use base64;
use hmac::digest::{BlockInput, FixedOutput, Reset, Update};
use hmac::Hmac;
use hmac::{Mac, NewMac};
use jwt_model::{Algorithm, SignedToken, UnsignedToken};
use sha2::{Sha256, Sha384, Sha512};

#[derive(Debug)]
pub enum Error {
    SerdeJson(serde_json::Error),
}

pub fn sign_token(token: UnsignedToken, key: &[u8]) -> Result<SignedToken, Error> {
    match token.header.alg {
        Algorithm::HS256 => sign_with_hmac::<Sha256>(token, key),
        Algorithm::HS384 => sign_with_hmac::<Sha384>(token, key),
        Algorithm::HS512 => sign_with_hmac::<Sha512>(token, key),
    }
}

fn sign_with_hmac<D>(unsigned_token: UnsignedToken, key: &[u8]) -> Result<SignedToken, Error>
where
    D: Update + BlockInput + FixedOutput + Reset + Default + Clone,
{
    let encoded_token = unsigned_token
        .encode()
        .map_err(|err| Error::SerdeJson(err))?;

    // Unrwap is safe, since hmac accepts keys of any length
    let mut hmac = Hmac::<D>::new_from_slice(key).unwrap();
    hmac.update(encoded_token.as_bytes());
    let output = hmac.finalize();

    let signature = base64::encode_config(
        output.into_bytes(),
        base64::Config::new(base64::CharacterSet::UrlSafe, false),
    );

    Ok(SignedToken::new(unsigned_token, signature))
}
