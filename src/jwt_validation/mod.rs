use crate::jwt_model;
use crate::jwt_signing;

use jwt_model::SignedToken;

#[derive(Debug)]
pub enum Error {
    SerdeJson(serde_json::Error),
}

pub fn validate_token(token: SignedToken, key: &[u8]) -> Result<bool, Error> {
    let token_signed_again_for_validation = jwt_signing::sign_token(token.unsigned_token, key)
        .map_err(|err| match err {
            jwt_signing::Error::SerdeJson(err) => Error::SerdeJson(err),
        })?;
    Ok(token_signed_again_for_validation.signature == token.signature)
}
