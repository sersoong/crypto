package aes

import (
	"github.com/gogf/gf/v2/crypto/gaes"
	"github.com/gogf/gf/v2/util/grand"
)

// GenKey Generate a new aes key.
func GenKey(lenth int) (key string) {
	key = grand.S(lenth)
	return
}

// EncryptAES Encrypt by aes
func EncryptAES(plaintext []byte, key []byte, iv []byte) (result []byte, err error) {
	result, err = gaes.Encrypt(plaintext, key, iv)
	return
}

// DecryptAES Decrypt by aes
func DecryptAES(ciphertext []byte, key []byte, iv []byte) (result []byte, err error) {
	result, err = gaes.Decrypt(ciphertext, key, iv)
	return
}
