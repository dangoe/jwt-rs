use crate::jwt_model;
use crate::jwt_signing;

use jwt_model::SignedToken;

pub fn validate(token: SignedToken, key: &[u8]) -> Result<bool, serde_json::Error> {
    let token_signed_again_for_validation = jwt_signing::sign(token.unsigned_token, key)?;
    Ok(token_signed_again_for_validation.signature == token.signature)
}
