package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
)

func main() {
	priv, _ := rsa.GenerateKey(rand.Reader, 3072)
	_ = rsa.SignPSS(rand.Reader, priv, 0, nil, nil)
	_, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, _ = mlkem.GenerateKey768()
}
