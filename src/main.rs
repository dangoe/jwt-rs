mod jwt_model;
mod jwt_signing;
mod jwt_validation;

use jwt_model::{Algorithm, ClaimsBuilder, Header, Type, UnsignedToken};
use serde_json::Value;

use std::fs::read_to_string;
use std::time::Instant;

fn main() {
    let token = UnsignedToken {
        header: Header {
            alg: Algorithm::RS512,
            typ: Type::JWT,
        },
        claims: ClaimsBuilder::new()
            .with_issuer(String::from("Chef"))
            .with_expiration_time(Instant::now().elapsed().as_secs().into())
            .with_custom(String::from("root"), Value::Bool(true))
            .build(),
    };

    let key = read_to_string("../../../jwt.key").unwrap();

    let der_encoded =
        key.lines()
            .filter(|line| !line.starts_with("-"))
            .fold(String::new(), |mut data, line| {
                data.push_str(&line);
                data
            });
    let der_bytes = base64::decode(&der_encoded).expect("failed to decode base64 content");

    let signed_token = jwt_signing::sign_token(token, &der_bytes).unwrap();
    println!("{:?}", signed_token.encode().unwrap());

    let public_key = read_to_string("../../../jwt.key.pub").unwrap();
    let der_encoded2 = public_key
        .lines()
        .filter(|line| !line.starts_with("-"))
        .fold(String::new(), |mut data, line| {
            data.push_str(&line);
            data
        });
    let der_bytes2 = base64::decode(&der_encoded2).expect("failed to decode base64 content");

    println!(
        "{:?}",
        jwt_validation::validate_token(signed_token, &der_bytes2[..])
    );
}
