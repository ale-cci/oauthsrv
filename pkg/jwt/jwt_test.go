package jwt_test

import (
	"fmt"
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

	t.Run("encode + decode should return same jwt-body fields", func(t *testing.T) {
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

	exampleTokens := []struct {
		Token string
		Head  *jwt.JWTHead
		Body  jwt.JWTBody
	}{
		{
			Token: "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.",
			Head:  &jwt.JWTHead{Alg: "none"},
			Body: jwt.JWTBody{
				"iss":                        "joe",
				"exp":                        1300819380,
				"http://example.com/is_root": true,
			},
		},
		{
			Token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			Head:  &jwt.JWTHead{Alg: "HS256", Typ: "JWT"},
			Body: jwt.JWTBody{
				"sub":  1234567890,
				"name": "John Doe",
				"iat":  1516239022,
			},
		},
	}

	t.Run("should read alg from jwt-head", func(t *testing.T) {
		for i, token := range exampleTokens {
			t.Run(fmt.Sprintf("Suite %d", i), func(t *testing.T) {
				decoded, err := jwt.Decode(token.Token)

				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				got := fmt.Sprint(decoded.Head)
				want := fmt.Sprint(token.Head)
				if got != want {
					t.Errorf("want: %q, got %q", want, got)
				}
			})
		}
	})

	t.Run("should read fields from jwt-body", func(t *testing.T) {
		for i, token := range exampleTokens {
			t.Run(fmt.Sprintf("Suite %d", i), func(t *testing.T) {
				decoded, err := jwt.Decode(token.Token)

				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				want := fmt.Sprint(token.Body)
				got := fmt.Sprint(decoded.Body)

				if want != got {
					t.Errorf("want: %q, got: %q", want, got)
				}
			})
		}
	})

	t.Run("should return error if token contains more than 3 chunks", func(t *testing.T) {
		_, err := jwt.Decode(exampleToken + ".")

		if err == nil {
			t.Errorf("Expected error, got %v", err)
		}
	})

	t.Run("should return error if token contains less than three chunks", func(t *testing.T) {
		_, err := jwt.Decode(".")

		if err == nil {
			t.Errorf("Expected error, got %v", err)
		}
	})
}
