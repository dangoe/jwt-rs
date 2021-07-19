use crate::jwt_model;
use crate::jwt_signing;
use hmac::digest::{BlockInput, FixedOutput, Reset, Update};
use jwt_model::{Algorithm, SignedToken};
use rsa::hash::Hash;
use rsa::{PaddingScheme, PublicKey, RSAPublicKey};
use sha2::{Sha256, Sha384, Sha512};

#[derive(Debug)]
pub enum Error {
    SerdeJson(serde_json::Error),
    RSA(rsa::errors::Error),
}

pub fn validate_token(token: SignedToken, key: &[u8]) -> Result<bool, Error> {
    match token.unsigned_token.header.alg {
        Algorithm::HS256 => validate_symmetric_hmac(token, key),
        Algorithm::HS384 => validate_symmetric_hmac(token, key),
        Algorithm::HS512 => validate_symmetric_hmac(token, key),
        Algorithm::RS256 => validate_asymmetric_rsa::<Sha256>(token, key, Hash::SHA2_256),
        Algorithm::RS384 => validate_asymmetric_rsa::<Sha384>(token, key, Hash::SHA2_384),
        Algorithm::RS512 => validate_asymmetric_rsa::<Sha512>(token, key, Hash::SHA2_512),
    }
}

fn validate_symmetric_hmac(token: SignedToken, key: &[u8]) -> Result<bool, Error> {
    let token_signed_again_for_validation = jwt_signing::sign_token(token.unsigned_token, key)
        .map_err(|err| match err {
            jwt_signing::Error::SerdeJson(err) => Error::SerdeJson(err),
            jwt_signing::Error::RSA(err) => Error::RSA(err),
        })?;
    Ok(token_signed_again_for_validation.signature == token.signature)
}

fn validate_asymmetric_rsa<D>(
    signed_token: SignedToken,
    der: &[u8],
    hash: Hash,
) -> Result<bool, Error>
where
    D: Update + BlockInput + FixedOutput + Reset + Default + Clone,
{
    let encoded_unsigned_token = signed_token
        .unsigned_token
        .encode()
        .map_err(|err| Error::SerdeJson(err))?;

    let mut hash_func = D::default();
    hash_func.update(encoded_unsigned_token);

    let hashed_encoded_unsigned_token = hash_func.finalize_fixed();

    let public_key = RSAPublicKey::from_pkcs1(der).map_err(|err| Error::RSA(err))?;
    match public_key.verify(
        PaddingScheme::PKCS1v15Sign { hash: Some(hash) },
        &hashed_encoded_unsigned_token[..],
        signed_token.signature.as_bytes(),
    ) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}
