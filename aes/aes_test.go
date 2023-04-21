package aes

import (
	"encoding/hex"
	"testing"
)

func TestGenKey(t *testing.T) {
	key := GenKey(16)
	t.Log(key)
}

func TestEncryptAES(t *testing.T) {
	key := "IjY0DqF6aiFeahRc"
	iv := "IjY0DqF6aiFeahRc"
	result, err := EncryptAES([]byte("helloworld"), []byte(key), []byte(iv))
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Log(hex.EncodeToString(result))
}

func TestDecryptAES(t *testing.T) {
	key := "IjY0DqF6aiFeahRc"
	iv := "IjY0DqF6aiFeahRc"
	raw, err := hex.DecodeString("fa53982fcdedaab982f7eb1a2d7b171a")
	if err != nil {
		t.Fatal(err.Error())
	}
	result, err := DecryptAES(raw, []byte(key), []byte(iv))
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Log(string(result))
}
