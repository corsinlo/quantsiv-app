import CryptoKit
let signing = P256.Signing.PrivateKey()
let agreement = Curve25519.KeyAgreement.PrivateKey()
let rsa = try _RSA.Signing.PrivateKey(keySize: .bits2048)
let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits as String: 3072]
let cipher = SecKeyCreateEncryptedData(key, .rsaEncryptionOAEPSHA256, data, nil)
