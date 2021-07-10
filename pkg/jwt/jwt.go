package jwt

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type JWT struct {
	Head *JWTHead
	Body JWTBody
}
type JWTHead struct {
	Alg string
	Typ string
}

type JWTBody map[string]interface{}

func (j *JWT) Encode(pk *rsa.PrivateKey) string {
	bytes, _ := json.Marshal(j.Body)
	body := base64.RawURLEncoding.EncodeToString(bytes)

	headBytes, _ := json.Marshal(j.Head)
	head := base64.RawURLEncoding.EncodeToString(headBytes)
	return head + "." + body + "."
}

func New(body JWTBody) *JWT {
	return &JWT{
		Body: body,
	}
}

func parseChunk(chunk string, into interface{}) error {
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

	if err := parseChunk(chunks[0], &jwtHead); err != nil {
		return nil, err
	}

	if err := parseChunk(chunks[1], &jwtBody); err != nil {
		return nil, err
	}

	return &JWT{&jwtHead, jwtBody}, nil
}
