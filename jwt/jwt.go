package jwt

import (
	"strings"
	"fmt"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
)

type JWT struct {
	Head *JWTHead
	Body JWTBody
}
type JWTHead struct {
	Alg string `json:"alg"`
}
type JWTBody map[string]string

func (j *JWT) Encode(pk *rsa.PrivateKey) string {
	bytes, _ :=  json.Marshal(j.Body)
	body := base64.RawURLEncoding.EncodeToString(bytes)
	return "." + body + "."
}

func New(body JWTBody) *JWT {
	return &JWT{
		Body: body,
	}
}

func Decode(token string) (*JWT, error) {
	chunks := strings.Split(token, ".")
	if amount := len(chunks); amount != 3 {
		return nil, fmt.Errorf("Wrong number of chunks, want 3, got %d", amount)
	}
	head, body := chunks[0], chunks[1]

	headDecoded, _ := base64.RawURLEncoding.DecodeString(head)
	bodyDecoded, _ := base64.RawURLEncoding.DecodeString(body)

	var jwtHead JWTHead
	var jwtBody JWTBody

	json.Unmarshal(headDecoded, &jwtHead)
	json.Unmarshal(bodyDecoded, &jwtBody)

	return &JWT{ &jwtHead, jwtBody}, nil
}
