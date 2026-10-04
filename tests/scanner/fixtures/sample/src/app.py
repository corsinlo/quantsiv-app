import jwt
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import ec, x25519

key = RSA.generate(2048)
cipher = PKCS1_OAEP.new(key.publickey())
curve_key = ec.generate_private_key(ec.SECP384R1())
shared = curve_key.exchange(ec.ECDH(), curve_key.public_key())
pk = x25519.X25519PrivateKey.generate()
token = jwt.encode({"sub": "u"}, "pem", algorithm="RS256")
