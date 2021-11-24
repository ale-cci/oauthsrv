package jwt

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ale-cci/oauthsrv/pkg/keystore"
)

type JWT struct {
	Head      *JWTHead
	Body      JWTBody
	Signature string
}

type JWTHead struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

type JWTBody map[string]interface{}

func (j JWT) Encode(ks PrivateKeyStore) (string, error) {
	payload, _ := j.SigPayload()
	signature, err := j.Sign(ks)
	if err != nil {
		return "", fmt.Errorf("Unable to sign custom token: %v", err)
	}
	return payload + "." + signature, nil
}

func decodeChunk(chunk string, into interface{}) error {
	decodedChunk, err := base64.RawURLEncoding.DecodeString(chunk)

	if err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(decodedChunk))
	decoder.UseNumber()

	return decoder.Decode(into)
}

func Decode(token string) (*JWT, error) {
	chunks := strings.Split(token, ".")
	if amount := len(chunks); amount != 3 {
		return nil, fmt.Errorf("Wrong number of chunks, want 3, got %d", amount)
	}

	var jwtHead JWTHead
	var jwtBody JWTBody

	if err := decodeChunk(chunks[0], &jwtHead); err != nil {
		return nil, err
	}

	if err := decodeChunk(chunks[1], &jwtBody); err != nil {
		return nil, err
	}

	return &JWT{&jwtHead, jwtBody, chunks[2]}, nil
}

type PubKeyGetter func(kid string) (*rsa.PublicKey, error)

func (j *JWT) SigPayload() (string, error) {
	headBytes, _ := json.Marshal(j.Head)
	bodyBytes, _ := json.Marshal(j.Body)

	encHead := base64.RawStdEncoding.EncodeToString(headBytes)
	encBody := base64.RawStdEncoding.EncodeToString(bodyBytes)

	return encHead + "." + encBody, nil
}

type PublicKeyStore interface {
	PublicKey(kid string) (*rsa.PublicKey, error)
}

func (j *JWT) Verify(ks PublicKeyStore) error {
	if j.Head.Alg == "none" {
		return fmt.Errorf("Tokens with algorithm 'none' could not be verified")
	}

	pubKey, err := ks.PublicKey(j.Head.Kid)
	if err != nil {
		return fmt.Errorf("Unable to verify jwt: %v", err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(j.Signature)
	if err != nil {
		return fmt.Errorf("Unable to decode signature: %v", err)
	}

	hasher := sha256.New()
	payload, _ := j.SigPayload()
	hasher.Write([]byte(payload))
	hash := hasher.Sum(nil)

	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], signature)
}

type PrivateKeyStore interface {
	PrivateKey(kid string) (*rsa.PrivateKey, error)
}

// Calculates token signature, base64-urlencoded
func (j JWT) Sign(ks PrivateKeyStore) (string, error) {
	hasher := sha256.New()
	payload, _ := j.SigPayload()
	hasher.Write([]byte(payload))
	hash := hasher.Sum(nil)

	var signature []byte

	if j.Head == nil || j.Head.Alg == "none" {
		signature = hash[:]
	} else {
		if ks == nil {
			return "", fmt.Errorf("PrivateKeystore not provided")
		}

		privKey, err := ks.PrivateKey(j.Head.Kid)
		if err != nil {
			return "", err
		}

		signature, err = rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
		if err != nil {
			return "", fmt.Errorf("Unable to sign jwt: %v", err)
		}
	}

	b64signature := base64.RawURLEncoding.EncodeToString(signature)
	return b64signature, nil
}

type KeySigner interface {
	GetSigningKey(alg string) (*keystore.PrivateKeyInfo, error)
	PrivateKey(kid string) (*rsa.PrivateKey, error)
}

func NewJWT(ks KeySigner, claims map[string]interface{}) (string, error) {

	keyInfo, _ := ks.GetSigningKey("HS256")

	// add protocol claims
	issuedAt := time.Now().Unix()
	claims["iat"] = issuedAt
	claims["exp"] = issuedAt + 3600

	token := JWT{
		Head: &JWTHead{
			Alg: keyInfo.Alg,
			Kid: keyInfo.KeyID,
		},
		Body: claims,
	}

	signed, err := token.Encode(ks)
	return signed, err
}
