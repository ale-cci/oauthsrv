package keystore

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

type TempKeystore struct {
	Keys map[string](*rsa.PrivateKey)
}

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

	kid := "1"
	ks.Keys[kid] = pk

	return &PrivateKeyInfo{
		Alg:        alg,
		KeyID:      kid, // TODO: random UUID
		PrivateKey: pk,
	}, nil
}

func (ks *TempKeystore) PublicKey(kid string) (*rsa.PublicKey, error) {
	return &ks.Keys[kid].PublicKey, nil
}

func (ks *TempKeystore) PrivateKey(kid string) (*rsa.PrivateKey, error) {
	return ks.Keys[kid], nil
}

func NewTempKeystore() (*TempKeystore, error) {
	return &TempKeystore{
		Keys: make(map[string](*rsa.PrivateKey)),
	}, nil
}
