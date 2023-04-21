package aes

import (
	"github.com/gogf/gf/v2/crypto/gaes"
	"github.com/gogf/gf/v2/util/grand"
)

func GenKey(lenth int) (key string) {
	key = grand.S(lenth)
	return
}

func EncryptAES(plaintext []byte, key []byte, iv []byte) (result []byte, err error) {
	result, err = gaes.Encrypt(plaintext, key, iv)
	return
}

func DecryptAES(ciphertext []byte, key []byte, iv []byte) (result []byte, err error) {
	result, err = gaes.Decrypt(ciphertext, key, iv)
	return
}
