package symetric

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"strconv"
)

type DecryptListResult struct {
	DecryptList []string `json:"encripted_list"`
	Err         error    `json:"error"`
}

func NewDecryptListResult() DecryptListResult {
	return DecryptListResult{
		DecryptList: []string{},
		Err:         nil,
	}
}

func DecryptTextList(cipherList []string, key []byte) ([]string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	decriptedList := make([]string, len(cipherList))
	for i, item := range cipherList {
		decripted, err := decriptString(item, block)
		if err != nil {
			return nil, errors.New("Error en desencriptación del item " + strconv.Itoa(i+1) + ":" + err.Error())
		}
		decriptedList[i] = decripted
	}
	return decriptedList, nil

}

func decriptString(ciphertext string, block cipher.Block) (string, error) {
	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("el texto cifrado es muy corto")
	}
	textBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", errors.New("Error en la decodificación del texto cifrado: " + err.Error())
	}
	iv := textBytes[:aes.BlockSize]
	textBytes = textBytes[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(textBytes, textBytes)

	return string(textBytes), nil
}
