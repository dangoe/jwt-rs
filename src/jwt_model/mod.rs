use base64;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::str;

#[derive(Copy, Clone, Serialize, Deserialize, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum Algorithm {
    HS256,
    HS384,
    HS512,
}

#[derive(Copy, Clone, Serialize, Deserialize, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum Type {
    JWT,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Header {
    pub alg: Algorithm,
    pub typ: Type,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Claims {
    #[serde(rename(serialize = "iss"), skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    #[serde(rename(serialize = "sub"), skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
    #[serde(rename(serialize = "aud"), skip_serializing_if = "Option::is_none")]
    audience: Option<String>,
    #[serde(rename(serialize = "exp"), skip_serializing_if = "Option::is_none")]
    expiration_time: Option<u128>,
    #[serde(rename(serialize = "nbf"), skip_serializing_if = "Option::is_none")]
    not_before: Option<u128>,
    #[serde(rename(serialize = "iat"), skip_serializing_if = "Option::is_none")]
    issued_at: Option<u128>,
    #[serde(rename(serialize = "jti"), skip_serializing_if = "Option::is_none")]
    jwt_id: Option<String>,
    #[serde(flatten)]
    custom: Map<String, Value>,
}

impl Claims {
    fn default() -> Claims {
        Claims {
            issuer: None,
            subject: None,
            audience: None,
            expiration_time: None,
            not_before: None,
            issued_at: None,
            jwt_id: None,
            custom: Map::default(),
        }
    }
}

pub struct ClaimsBuilder {
    issuer: Option<String>,
    subject: Option<String>,
    audience: Option<String>,
    expiration_time: Option<u128>,
    not_before: Option<u128>,
    issued_at: Option<u128>,
    jwt_id: Option<String>,
    custom: Map<String, Value>,
}

impl ClaimsBuilder {
    pub fn new() -> ClaimsBuilder {
        ClaimsBuilder {
            issuer: None,
            subject: None,
            audience: None,
            expiration_time: None,
            not_before: None,
            issued_at: None,
            jwt_id: None,
            custom: Map::default(),
        }
    }

    pub fn with_issuer(mut self, issuer: String) -> Self {
        self.issuer = Some(issuer);
        self
    }

    pub fn with_subject(mut self, subject: String) -> Self {
        self.subject = Some(subject);
        self
    }

    pub fn with_audience(mut self, audience: String) -> Self {
        self.audience = Some(audience);
        self
    }

    pub fn with_expiration_time(mut self, expiration_time: u128) -> Self {
        self.expiration_time = Some(expiration_time);
        self
    }

    pub fn with_not_before(mut self, not_before: u128) -> Self {
        self.not_before = Some(not_before);
        self
    }

    pub fn with_issued_at(mut self, issued_at: u128) -> Self {
        self.issued_at = Some(issued_at);
        self
    }

    pub fn with_jwt_id(mut self, jwt_id: String) -> Self {
        self.jwt_id = Some(jwt_id);
        self
    }

    pub fn with_custom(mut self, key: String, value: Value) -> Self {
        self.custom.insert(key, value);
        self
    }

    pub fn build(self) -> Claims {
        Claims {
            issuer: self.issuer,
            subject: self.subject,
            audience: self.audience,
            expiration_time: self.expiration_time,
            not_before: self.not_before,
            issued_at: self.issued_at,
            jwt_id: self.jwt_id,
            custom: self.custom,
        }
    }
}

#[derive(Clone, Debug)]
pub struct UnsignedToken {
    pub header: Header,
    pub claims: Claims,
}

impl UnsignedToken {
    pub fn encode(&self) -> Result<String, serde_json::Error> {
        let header = encode_base64(&self.header)?;
        let claims = encode_base64(&self.claims)?;
        Ok(format!("{}.{}", header, claims))
    }
}

fn encode_base64<T>(t: &T) -> Result<String, serde_json::Error>
where
    T: Serialize,
{
    let json = (serde_json::to_string(t))?;
    let base64_encoded = base64::encode_config(
        json,
        base64::Config::new(base64::CharacterSet::UrlSafe, false),
    );
    Ok(base64_encoded)
}

#[derive(Clone, Debug)]
pub struct SignedToken {
    pub unsigned_token: UnsignedToken,
    pub signature: String,
}

impl SignedToken {
    pub fn new(unsigned_token: UnsignedToken, signature: String) -> SignedToken {
        SignedToken {
            unsigned_token: unsigned_token,
            signature: signature,
        }
    }

    pub fn encode(&self) -> Result<String, serde_json::Error> {
        let encoded_unsigned_token = self.unsigned_token.encode()?;
        Ok(format!("{}.{}", encoded_unsigned_token, self.signature))
    }
}
