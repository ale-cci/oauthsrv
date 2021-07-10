package jwt_test

import (
	"github.com/ale-cci/oauthsrv/pkg/jwt"
	"strings"
	"testing"
)

func TestJWT(t *testing.T) {
	t.Run("Token should be composed by three chunks, separated by dot", func(t *testing.T) {
		token := jwt.New(nil).Encode(nil)
		chunks := strings.Split(token, ".")

		got := len(chunks)
		want := 3
		if got != want {
			t.Errorf("want: %d, got: %d", want, got)
		}
	})

	t.Run("Same field should return back if token is decoded", func(t *testing.T) {
		token := jwt.New(jwt.JWTBody{
			"iss": "myself",
		}).Encode(nil)
		decoded, err := jwt.Decode(token)

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		got := decoded.Body["iss"]
		want := "myself"
		if got != want {
			t.Errorf("want: %q, got %q", want, got)
		}
	})
}

func TestDecode(t *testing.T) {
	exampleToken := "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."

	// example from https://datatracker.ietf.org/doc/html/rfc7519#appendix-A.1
	t.Run("should parse head algorithm correctly", func(t *testing.T) {
		token, err := jwt.Decode(exampleToken)

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		got := token.Head.Alg
		want := "none"
		if got != want {
			t.Errorf("want: %q, got %q", want, got)
		}
	})

	t.Run("should correctly get three fields from body", func(t *testing.T) {
		token, err := jwt.Decode(exampleToken)

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		got := token.Body["iss"]
		want := "joe"

		if got != want {
			t.Errorf("want: %q, got %q", want, got)
		}
	})

	t.Run("should return error if chunks are higher than three", func(t *testing.T) {
		_, err := jwt.Decode(exampleToken + ".")

		if err == nil {
			t.Errorf("Expected error, got %v", err)
		}
	})

	t.Run("should return error if chunks are less than three", func(t *testing.T) {
		_, err := jwt.Decode(".")

		if err == nil {
			t.Errorf("Expected error, got %v", err)
		}
	})
}
