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

func (j JWT) Encode(ks keystore.PrivateKeystore) (string, error) {
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

func (j *JWT) SigPayload() (string, error) {
	headBytes, _ := json.Marshal(j.Head)
	bodyBytes, _ := json.Marshal(j.Body)

	encHead := base64.RawStdEncoding.EncodeToString(headBytes)
	encBody := base64.RawStdEncoding.EncodeToString(bodyBytes)

	return encHead + "." + encBody, nil
}

func (j *JWT) Verify(ks keystore.PublicKeystore) error {
	if j.Head.Alg == "none" {
		return fmt.Errorf("Tokens with algorithm 'none' could not be verified")
	}

	if exp, ok := j.Body["exp"]; ok {
		var expiryDateTime int64

		if value, ok := exp.(int64); ok {
			expiryDateTime = value
		} else if value, ok := exp.(json.Number); ok {
			jsonValue, _ := value.Float64()
			expiryDateTime = int64(jsonValue)
		} else {
			return fmt.Errorf("Unable to decode jwt token: invalid `exp` value")
		}

		now := time.Now().Unix()
		if expiryDateTime <= now {
			return fmt.Errorf("JWT is expired")
		}
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

// Calculates token signature, base64-urlencoded
func (j JWT) Sign(ks keystore.PrivateKeystore) (string, error) {
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

// Generate new signed JWT, containing the provided claims
// requires a private key provider to sign the jwt.
func NewJWT(ks keystore.PrivateKeyProvider, claims map[string]interface{}) (string, error) {
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
