use falcon2017::{Error, PublicKey, SecretKey};

#[test]
fn malformed_public_key_is_rejected() {
    let err = PublicKey::<9>::from_bytes(&[0x10, 0x00, 0x00]).expect_err("must reject");
    assert_eq!(err, Error::InvalidEncoding);
}

#[test]
fn malformed_secret_key_is_rejected() {
    match SecretKey::<9>::from_bytes(&[0x29, 0x00, 0x00]) {
        Ok(_) => panic!("must reject malformed secret key"),
        Err(err) => assert_eq!(err, Error::InvalidEncoding),
    }
}
