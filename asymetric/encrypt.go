package asymetric

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

func EncryptTextWithPublicKey(text string, publicKeyPEM []byte) (string, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return "", errors.New("error en procesamiento PEM de llave publica")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("error en procesamiento de llave publica")
	}
	textBytes := []byte(text)
	ciphertext, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		textBytes,
		nil,
	)
	if err != nil {
		return "", errors.New("falla en la cifrado del texto: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
