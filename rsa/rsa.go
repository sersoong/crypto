package rsa

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/gogf/gf/v2/os/gfile"
	"github.com/gogf/gf/v2/os/glog"
	"math/big"
	"time"
)

// Generate RSA Keypair to []byte
func GenerateRSAKeypair(ctx context.Context) (prikey, pubkey []byte, err error) {
	prikey = nil
	pubkey = nil
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		glog.Line(true).Notice(ctx, err.Error())
		return
	}
	prikey = x509.MarshalPKCS1PrivateKey(priv)
	pubkey = x509.MarshalPKCS1PublicKey(&priv.PublicKey)
	return
}

// Encrypt By RSA using []byte format key
func EncryptRSA(ctx context.Context, plaintext []byte, publickey []byte) (result []byte, err error) {
	result = nil
	pubkey, err := x509.ParsePKCS1PublicKey(publickey)
	if err != nil {
		glog.Line(true).Notice(ctx, err.Error())
		return
	}
	result, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pubkey, plaintext, nil)
	return
}

// Decrypt By RSA using []byte format key
func DecryptRSA(ctx context.Context, ciphertext []byte, privatekey []byte) (result []byte, err error) {
	result = nil
	prikey, err := x509.ParsePKCS1PrivateKey(privatekey)
	if err != nil {
		glog.Line(true).Notice(ctx, err.Error())
		return
	}
	result, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, prikey, ciphertext, nil)
	return
}

// Generate Tls certificate
func GenCertificate() (cert tls.Certificate, err error) {
	rawCert, rawKey, err := GenerateCert()
	if err != nil {
		return
	}
	return tls.X509KeyPair(rawCert, rawKey)
}

// Create private key and self-signed certificate
func GenerateCert(organization []string) (rawCert, rawKey []byte, err error) {
	// Adapted from https://golang.org/src/crypto/tls/generate_cert.go
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	validFor := time.Hour * 24 * 365 * 10 // ten years
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: organization,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return
	}
	rawCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	rawKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return
}

// write certs files to storage
func WriteCerts(ctx context.Context, path string, name string) (err error) {
	cert, key, err := GenerateCert()
	if err != nil {
		glog.Line(true).Notice(ctx, err.Error())
		return err
	}

	certFileName := fmt.Sprintf("%s/%s.crt", path, name)
	keyFileName := fmt.Sprintf("%s/%s.key", path, name)

	err = gfile.PutBytes(certFileName, cert)
	if err != nil {
		glog.Line(true).Notice(ctx, err.Error())
		return err
	}
	err = gfile.PutBytes(keyFileName, key)
	if err != nil {
		glog.Line(true).Notice(ctx, err.Error())
		return err
	}
	return nil
}
