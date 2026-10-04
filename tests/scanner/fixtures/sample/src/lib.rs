use openssl::rsa::Rsa;
use ring::signature;
fn keys() {
    let rsa = Rsa::generate(2048).unwrap();
    let alg = &signature::ECDSA_P256_SHA256_ASN1_SIGNING;
}
