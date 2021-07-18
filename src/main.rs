mod jwt_model;
mod jwt_signing;
mod jwt_validation;

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

    let signed_token = jwt_signing::sign(token, key).unwrap();
    println!("{:?}", signed_token.encode().unwrap());
    println!(
        "{}",
        jwt_validation::validate(signed_token.clone(), String::from("a").as_bytes()).unwrap()
    );
    println!("{}", jwt_validation::validate(signed_token.clone(), key).unwrap());
}
