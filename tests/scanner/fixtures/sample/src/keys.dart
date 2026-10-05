import 'package:pointycastle/export.dart';
final params = RSAKeyGeneratorParameters(BigInt.from(65537), 2048, 64);
final gen = RSAKeyGenerator()..init(ParametersWithRandom(params, rng));
final ec = ECKeyGenerator()..init(ParametersWithRandom(ECKeyGeneratorParameters(ECCurve_secp256r1()), rng));
final signer = ECDSASigner(SHA256Digest(), HMac(SHA256Digest(), 64));
final x = X25519();
final ed = Ed25519();
final ecdh = Ecdh.p384(length: 32);
