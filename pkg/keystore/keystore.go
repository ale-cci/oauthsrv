/**
 * A keystore is used to get or retrieve keys, for
 * signing or validating jwts.
 */
package keystore

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/google/uuid"
)

type Keystore interface {
	PublicKey(kid string) (*rsa.PublicKey, error)
	PrivateKey(kid string) (*rsa.PrivateKey, error)
	GetSigningKey(alg string) (*PrivateKeyInfo, error)
}

/**
 * Volatile Keystore, keys are generated on the fly when
 * requested.
 * When the application shuts off, all the keys are lost.
 */
type TempKeystore struct {
	Keys map[string](*PrivateKeyInfo)
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
	if alg != "HS256" {
		return nil, fmt.Errorf("Signing algorithm not recognize")
	}
	if len(ks.Keys) > 0 {
		for _, value := range ks.Keys {
			return value, nil
		}
	}

	pk, err := rsa.GenerateKey(rand.Reader, 2096)

	if err != nil {
		return nil, fmt.Errorf("Unable to generate private key: %v", err)
	}

	kid := uuid.New().String()

	keyInfo := &PrivateKeyInfo{
		Alg:        alg,
		KeyID:      kid,
		PrivateKey: pk,
	}
	ks.Keys[kid] = keyInfo

	return keyInfo, nil
}

/**
 * Fetch a private key given it's key id
 */
func (ks *TempKeystore) PublicKey(kid string) (*rsa.PublicKey, error) {
	keyInfo, ok := ks.Keys[kid]
	if !ok {
		return nil, fmt.Errorf("Key %v not registered", kid)
	}
	return &keyInfo.PrivateKey.PublicKey, nil
}

/**
 * Fetch a public key given it's key id
 */
func (ks *TempKeystore) PrivateKey(kid string) (*rsa.PrivateKey, error) {
	keyInfo, ok := ks.Keys[kid]
	if !ok {
		return nil, fmt.Errorf("Key %v not registered", kid)
	}
	return keyInfo.PrivateKey, nil
}

func NewTempKeystore() (*TempKeystore, error) {
	return &TempKeystore{
		Keys: make(map[string](*PrivateKeyInfo)),
	}, nil
}
