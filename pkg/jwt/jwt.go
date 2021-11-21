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

func (j JWT) Encode(ks PrivateKeyStore) string {
	payload, _ := j.SigPayload()
	signature, _ := j.Sign(ks)
	return payload + "." + signature
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

	return &JWT{&jwtHead, jwtBody, ""}, nil
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
	PublicKey(alg, kid string) (*rsa.PublicKey, error)
}

func (j *JWT) Verify(ks PublicKeyStore) error {
	if j.Head.Alg == "none" {
		return fmt.Errorf("Tokens with algorithm 'none' could not be verified")
	}

	pubKey, _ := ks.PublicKey("", "")
	signature, _ := base64.RawURLEncoding.DecodeString(j.Signature)

	hasher := sha256.New()
	payload, _ := j.SigPayload()
	hasher.Write([]byte(payload))
	hash := hasher.Sum(nil)

	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], signature)
}

type PrivateKeyStore interface {
	PrivateKey(alg, kid string) (*rsa.PrivateKey, error)
}

// Calculates token signature, base64-urlencoded
func (j JWT) Sign(ks PrivateKeyStore) (string, error) {
	hasher := sha256.New()
	payload, _ := j.SigPayload()
	hasher.Write([]byte(payload))
	hash := hasher.Sum(nil)

	if ks == nil {
		return "", fmt.Errorf("PrivateKeystore not provided")
	}

	privKey, err := ks.PrivateKey("", "")
	if err != nil {
		return "", err
	}

	signature, _ := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])

	b64signature := base64.RawURLEncoding.EncodeToString(signature)
	return b64signature, nil
}
