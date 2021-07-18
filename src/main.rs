mod jwt_model;
mod jwt_signing;

use jwt_model::{Algorithm, ClaimsBuilder, Header, Type, UnsignedToken};
use serde_json::Value;

use std::time::Instant;

fn main() {
    let key = "secret".as_bytes();

    let token = UnsignedToken {
        header: Header {
            alg: Algorithm::HS512,
            typ: Type::JWT,
        },
        claims: ClaimsBuilder::new()
            .with_issuer(String::from("Chef"))
            .with_expiration_time(Instant::now().elapsed().as_secs().into())
            .with_custom(String::from("root"), Value::Bool(true))
            .build(),
    };

    println!("{}", jwt_signing::sign(token, key).unwrap());
}
