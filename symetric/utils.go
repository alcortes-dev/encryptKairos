package symetric

import (
	"crypto/rand"
	"errors"
)

func CreateSymmetricKey(keySize int) ([]byte, error) {
	key := make([]byte, keySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, errors.New("Failed to generate key: " + err.Error())
	}
	return key, nil
}

func Create256BitesKey() ([]byte, error) {
	return CreateSymmetricKey(32)
}

func Create1024BitesKey() ([]byte, error) {
	return CreateSymmetricKey(128)
}

func Create2048BitesKey() ([]byte, error) {
	return CreateSymmetricKey(256)
}
