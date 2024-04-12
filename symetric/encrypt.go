package symetric

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strconv"
)

type EncryptionListResult struct {
	EncriptedList []string `json:"encripted_list"`
	Key           []byte   `json:"key"`
	Err           error    `json:"error"`
}

func NewEncryptionListResult() EncryptionListResult {
	return EncryptionListResult{
		EncriptedList: []string{},
		Err:           nil,
		Key:           []byte{},
	}
}

func EncryptTextList(textList []string) EncryptionListResult { //([]string, []byte, error) {
	result := NewEncryptionListResult()
	keySize := 32
	key, err := CreateSymmetricKey(keySize)
	if err != nil {
		result.Err = errors.New("Error al generar la llave:" + err.Error())
		return result
	}
	result.Key = key
	block, err := aes.NewCipher(key)
	if err != nil {
		result.Err = errors.New("Error al crear el bloque:" + err.Error())
		return result
	}

	encriptedList := []string{}

	for i, item := range textList {
		encripted, err := encriptString(item, block)
		if err != nil {
			result.Err = errors.New("Error en encriptación del item " + strconv.Itoa(i+1) + ":" + err.Error())
			return result
		}
		encriptedList = append(encriptedList, encripted)
	}
	result.EncriptedList = encriptedList
	return result
}

//export encriptString
func encriptString(text string, block cipher.Block) (string, error) {
	textBytes := []byte(text)

	ciphertext := make([]byte, aes.BlockSize+len(textBytes))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], textBytes)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
