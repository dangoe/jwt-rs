use crate::jwt_model;

use base64;
use hmac::digest::{BlockInput, FixedOutput, Reset, Update};
use hmac::Hmac;
use hmac::{Mac, NewMac};
use jwt_model::{Algorithm, SignedToken, UnsignedToken};
use rsa::hash::Hash;
use rsa::{PaddingScheme, RSAPrivateKey};
use sha2::{Sha256, Sha384, Sha512};

#[derive(Debug)]
pub enum Error {
    SerdeJson(serde_json::Error),
    RSA(rsa::errors::Error),
}

pub fn sign_token(token: UnsignedToken, key: &[u8]) -> Result<SignedToken, Error> {
    match token.header.alg {
        Algorithm::HS256 => sign_with_symmetric_hmac::<Sha256>(token, key),
        Algorithm::HS384 => sign_with_symmetric_hmac::<Sha384>(token, key),
        Algorithm::HS512 => sign_with_symmetric_hmac::<Sha512>(token, key),
        Algorithm::RS256 => sign_with_rsa::<Sha256>(token, key, Hash::SHA2_256),
        Algorithm::RS384 => sign_with_rsa::<Sha384>(token, key, Hash::SHA2_384),
        Algorithm::RS512 => sign_with_rsa::<Sha512>(token, key, Hash::SHA2_512),
    }
}

fn sign_with_symmetric_hmac<D>(
    unsigned_token: UnsignedToken,
    key: &[u8],
) -> Result<SignedToken, Error>
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

fn sign_with_rsa<D>(
    unsigned_token: UnsignedToken,
    der: &[u8],
    hash: Hash,
) -> Result<SignedToken, Error>
where
    D: Update + BlockInput + FixedOutput + Reset + Default + Clone,
{
    let encoded_unsigned_token = unsigned_token
        .encode()
        .map_err(|err| Error::SerdeJson(err))?;

    let mut hash_func = D::default();
    hash_func.update(encoded_unsigned_token);

    let hashed_encoded_unsigned_token = hash_func.finalize_fixed();

    let private_key = RSAPrivateKey::from_pkcs1(der).map_err(|err| Error::RSA(err))?;
    let output = private_key
        .sign(
            PaddingScheme::PKCS1v15Sign { hash: Some(hash) },
            &hashed_encoded_unsigned_token[..],
        )
        .map_err(|err| Error::RSA(err))?;

    let signature = base64::encode_config(
        output,
        base64::Config::new(base64::CharacterSet::UrlSafe, false),
    );
    Ok(SignedToken::new(unsigned_token, signature))
}
