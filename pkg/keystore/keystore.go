package keystore

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

type TempKeystore struct{}

type PrivateKeyInfo struct {
	Alg        string
	KeyID      string
	PrivateKey *rsa.PrivateKey
}

func (ks *TempKeystore) GetSigningKey(alg string) (*PrivateKeyInfo, error) {
	pk, err := rsa.GenerateKey(rand.Reader, 2096)

	if err != nil {
		return nil, fmt.Errorf("Unable to generate private key: %v", err)
	}

	return &PrivateKeyInfo{
		Alg:        alg,
		KeyID:      "1", // TODO: random UUID
		PrivateKey: pk,
	}, nil
}

func NewTempKeystore() (*TempKeystore, error) {
	return &TempKeystore{}, nil
}
