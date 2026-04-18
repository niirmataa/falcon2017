mod common;

use common::FixedSeedRng;
use falcon2017::{Compression, Falcon1024, Falcon512, PublicKey, SecretKey};

#[test]
fn public_and_secret_key_roundtrip_for_falcon512() {
    let mut rng = FixedSeedRng::new(*b"falcon2017-step19-encode-512-key");
    let keypair = Falcon512::keygen(&mut rng).expect("keygen");

    let public = PublicKey::<9>::from_bytes(keypair.public.to_bytes()).expect("public key");
    assert_eq!(public.to_bytes(), keypair.public.to_bytes());

    let sk_none = keypair.secret.to_bytes(Compression::None);
    let sk_none_roundtrip = SecretKey::<9>::from_bytes(&sk_none).expect("secret key");
    assert_eq!(&*sk_none_roundtrip.to_bytes(Compression::None), &*sk_none);

    let sk_static = keypair.secret.to_bytes(Compression::Static);
    let sk_static_roundtrip = SecretKey::<9>::from_bytes(&sk_static).expect("secret key");
    assert_eq!(
        &*sk_static_roundtrip.to_bytes(Compression::Static),
        &*sk_static
    );
}

#[test]
fn public_and_secret_key_roundtrip_for_falcon1024() {
    let mut rng = FixedSeedRng::new(*b"falcon2017-step19-encode-1024-ke");
    let keypair = Falcon1024::keygen(&mut rng).expect("keygen");

    let public = PublicKey::<10>::from_bytes(keypair.public.to_bytes()).expect("public key");
    assert_eq!(public.to_bytes(), keypair.public.to_bytes());

    let sk_none = keypair.secret.to_bytes(Compression::None);
    let sk_none_roundtrip = SecretKey::<10>::from_bytes(&sk_none).expect("secret key");
    assert_eq!(&*sk_none_roundtrip.to_bytes(Compression::None), &*sk_none);

    let sk_static = keypair.secret.to_bytes(Compression::Static);
    let sk_static_roundtrip = SecretKey::<10>::from_bytes(&sk_static).expect("secret key");
    assert_eq!(
        &*sk_static_roundtrip.to_bytes(Compression::Static),
        &*sk_static
    );
}
