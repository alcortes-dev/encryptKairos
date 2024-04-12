package asymetric

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

func DecryptTextWithPrivateKey(ciphertext string, privateKeyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKeyPEM)

	if block == nil {
		return nil, errors.New("error en procesamiento PEM de llave privada")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, errors.New("falla en la decodificación del texto cifrado: " + err.Error())
	}
	plaintext, err := rsa.DecryptOAEP(
		sha256.New(),
		nil,
		priv.(*rsa.PrivateKey),
		ciphertextBytes,
		nil,
	)
	if err != nil {
		return nil, errors.New("falla en la descifrado del texto: " + err.Error())
	}
	return plaintext, nil
}
