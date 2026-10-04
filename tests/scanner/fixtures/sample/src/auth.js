const { generateKeyPairSync, createECDH, publicEncrypt } = require("crypto");
const pair = generateKeyPairSync("rsa", { modulusLength: 4096 });
const ecdh = createECDH("prime256v1");
const blob = publicEncrypt(pair.publicKey, Buffer.from("x"));
const jwtOptions = { algorithm: "ES256" };
