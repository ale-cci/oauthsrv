package passwords

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

type Algorithm = string

const (
	SHA256 Algorithm = "sha256"
)

func New(rng io.Reader, password string) (string, error) {
	salt := make([]byte, 12)
	_, err := io.ReadFull(rng, salt)
	if err != nil {
		return "", err
	}

	return Encode(SHA256, base64.RawStdEncoding.EncodeToString(salt), password)
}

func Encode(alg Algorithm, salt, password string) (string, error) {
	if alg != SHA256 {
		return "", fmt.Errorf("Unexpected algorithm name: %q", alg)
	}

	hasher := sha256.New()
	hasher.Write([]byte(salt + password))
	hash := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))

	pass := alg + "$" + salt + "$" + hash
	return pass, nil
}

func Validate(hashed, plain string) error {
	chunks := strings.Split(hashed, "$")
	alg, salt, _ := chunks[0], chunks[1], chunks[2]

	enc, err := Encode(alg, salt, plain)
	if err != nil {
		return err
	}

	if enc != hashed {
		return fmt.Errorf("Mismatching passwords")
	}
	return nil
}
