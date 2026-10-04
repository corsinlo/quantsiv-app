const key = await crypto.subtle.generateKey({ name: "RSA-OAEP", modulusLength: 3072, hash: "SHA-256" }, true, ["encrypt"]);
const sig = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-521" }, true, ["sign"]);
