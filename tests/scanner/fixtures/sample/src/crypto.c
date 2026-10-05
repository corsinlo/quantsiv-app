#include <openssl/rsa.h>
#include <openssl/evp.h>

int make_keys(RSA *rsa, EC_KEY *ec, BIGNUM *e) {
    RSA_generate_key_ex(rsa, 2048, e, NULL);
    EVP_PKEY_CTX *kx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    ECDSA_do_sign(digest, 32, ec);
    RSA_public_encrypt(len, in, out, rsa, RSA_PKCS1_OAEP_PADDING);
    mbedtls_rsa_gen_key(&rsa_ctx, mbedtls_ctr_drbg_random, &ctr_drbg, 3072, 65537);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP384R1);
    crypto_box_keypair(pk, sk);
    crypto_sign_detached(sig, &siglen, m, mlen, sk);
    wc_MakeRsaKey(&key, 4096, WC_RSA_EXPONENT, &rng);
    BCryptOpenAlgorithmProvider(&h, BCRYPT_ECDH_P256_ALGORITHM, NULL, 0);
    EVP_PKEY *pq = EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-768");
    return 0;
}
