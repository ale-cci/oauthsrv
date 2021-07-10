package passwords_test

import (
	"crypto/rand"
	"github.com/ale-cci/oauthsrv/pkg/passwords"
	"strings"
	"testing"
)

func TestNewPassword(t *testing.T) {
	t.Run("Password should be validated without errors", func(t *testing.T) {
		pass, err := passwords.New(rand.Reader, "test")
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		err = passwords.Validate(pass, "test")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	})

	t.Run("Validate should return error when password differs", func(t *testing.T) {
		tt := []struct {
			Password, CheckPassword string
		}{
			{"test", "testo"},
			{"test", "test2"},
		}

		for _, tc := range tt {
			pass, err := passwords.New(rand.Reader, tc.Password)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			err = passwords.Validate(pass, tc.CheckPassword)

			if err == nil {
				t.Fatalf("expected error on password validation, got: %v", err)
			}
		}
	})

	t.Run("Validate password format", func(t *testing.T) {
		pass, err := passwords.New(rand.Reader, "x")
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		chunks := strings.Split(pass, "$")

		got := len(chunks)
		want := 3

		if got != want {
			t.Fatalf("want: %d, got: %d", want, got)
		}
	})

	t.Run("2 passwords should likely have different salt", func(t *testing.T) {
		rng := rand.Reader
		var err error
		var pass1, pass2 string

		if pass1, err = passwords.New(rng, "pass"); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if pass2, err = passwords.New(rng, "pass"); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if pass1 == pass2 {
			t.Fatalf("Passwords are identical: %q %q", pass1, pass2)
		}
	})
}

func TestPasswordFormat(t *testing.T) {
	t.Run("Encode should hash with sha function", func(t *testing.T) {
		got, err := passwords.Encode(passwords.SHA256, "1234", "plaintext")
		want := "sha256$1234$sZnzRUrnWRyYxYDqR3wLo432yLi-PCSBuFAy4Q0Rs9I"

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if got != want {
			t.Errorf("want: %q, got %q", want, got)
		}
	})

	t.Run("Encoded password should be validable from Validate", func(t *testing.T) {
		enc, err := passwords.Encode(passwords.SHA256, "123", "plaintext")
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		err = passwords.Validate(enc, "plaintext")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	})

	t.Run("should return error if algorithm is not recognized", func(t *testing.T) {
		_, err := passwords.Encode("sha257", "123", "plaintext")
		if err == nil {
			t.Errorf("Expected error, got %v", err)
		}
	})
}
