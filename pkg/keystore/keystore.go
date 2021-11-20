/**
 * A keystore is used to get or retrieve keys, for
 * signing or validating jwts.
 */
package keystore

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

/**
 * Volatile Keystore, keys are generated on the fly when
 * requested.
 * When the application shuts off, all the keys are lost.
 */
type TempKeystore struct {
	Keys map[string](*rsa.PrivateKey)
}

type PrivateKeyInfo struct {
	Alg        string
	KeyID      string
	PrivateKey *rsa.PrivateKey
}

/**
 * Get the signing key from the keystore. If none exist one
 * is created
 * Ideally private keys should have an expiration date, and
 * rotate.
 */
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

/**
 * Fetch a private key given it's key id
 */
func (ks *TempKeystore) PublicKey(kid string) (*rsa.PublicKey, error) {
	return &ks.Keys[kid].PublicKey, nil
}

/**
 * Fetch a public key given it's key id
 */
func (ks *TempKeystore) PrivateKey(kid string) (*rsa.PrivateKey, error) {
	return ks.Keys[kid], nil
}

func NewTempKeystore() (*TempKeystore, error) {
	return &TempKeystore{
		Keys: make(map[string](*rsa.PrivateKey)),
	}, nil
}
