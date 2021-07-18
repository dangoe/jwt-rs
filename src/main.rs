use base64;
use hmac::digest::{BlockInput, FixedOutput, Reset, Update};
use hmac::Hmac;
use hmac::{Mac, NewMac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Sha256, Sha384, Sha512};
use std::str;

#[derive(Copy, Clone, Serialize, Deserialize, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
enum Algorithm {
    HS256,
    HS384,
    HS512,
}

#[derive(Copy, Clone, Serialize, Deserialize, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
enum Type {
    JWT,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct Header {
    alg: Algorithm,
    typ: Type,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct Claims {
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

struct ClaimsBuilder {
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
    fn new() -> ClaimsBuilder {
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

    fn with_issuer(mut self, issuer: String) -> Self {
        self.issuer = Some(issuer);
        self
    }

    fn with_subject(mut self, subject: String) -> Self {
        self.subject = Some(subject);
        self
    }

    fn with_audience(mut self, audience: String) -> Self {
        self.subject = Some(audience);
        self
    }

    fn with_expiration_time(mut self, expiration_time: String) -> Self {
        self.subject = Some(expiration_time);
        self
    }

    fn with_not_before(mut self, not_before: String) -> Self {
        self.subject = Some(not_before);
        self
    }

    fn with_issued_at(mut self, issued_at: String) -> Self {
        self.subject = Some(issued_at);
        self
    }

    fn with_jwt_id(mut self, jwt_id: String) -> Self {
        self.subject = Some(jwt_id);
        self
    }

    fn with_custom(mut self, key: String, value: Value) -> Self {
        self.custom.insert(key, value);
        self
    }

    fn build(self) -> Claims {
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
struct Token {
    header: Header,
    claims: Claims,
}

impl Token {
    fn encode(&self) -> Result<String, serde_json::Error> {
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

fn main() {
    let key = "secret".as_bytes();

    let token = Token {
        header: Header {
            alg: Algorithm::HS512,
            typ: Type::JWT,
        },
        claims: ClaimsBuilder::new()
            .with_issuer(String::from("a"))
            .with_custom(String::from("a"), Value::String(String::from("a")))
            .build(),
    };

    match token.header.alg {
        Algorithm::HS256 => {
            println!("{}", encode_hmac::<Sha256>(token, key).unwrap());
        }
        Algorithm::HS384 => {
            println!("{}", encode_hmac::<Sha384>(token, key).unwrap());
        }
        Algorithm::HS512 => {
            println!("{}", encode_hmac::<Sha512>(token, key).unwrap());
        }
    };
}

fn encode_hmac<D>(token: Token, key: &[u8]) -> Result<String, serde_json::Error>
where
    D: Update + BlockInput + FixedOutput + Reset + Default + Clone,
{
    let mut hmac = Hmac::<D>::new_from_slice(key).expect("HMAC is able to accept all key sizes");
    let encoded_json = token.encode()?;
    hmac.update(encoded_json.as_bytes());
    let output = hmac.finalize();
    let signature = base64::encode_config(
        output.into_bytes(),
        base64::Config::new(base64::CharacterSet::UrlSafe, false),
    );
    Ok(format!("{}.{}", encoded_json, signature))
}
