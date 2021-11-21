package jwt_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/ale-cci/oauthsrv/pkg/jwt"
	"github.com/ale-cci/oauthsrv/pkg/keystore"
	"gotest.tools/assert"
)

type TestMemoryKeystore struct{}

func (mks *TestMemoryKeystore) PrivateKey(kid string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw
kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr
m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi
NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV
3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2
QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs
kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go
amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM
+bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9
D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC
0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y
lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+
hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp
bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X
+jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B
BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC
2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx
QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz
5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9
Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0
NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j
8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma
3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K
y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB
jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=
-----END RSA PRIVATE KEY-----`))

	pk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pk, pk.Validate()
}

func (mks *TestMemoryKeystore) PublicKey(kid string) (*rsa.PublicKey, error) {
	key, err := mks.PrivateKey(kid)
	if err != nil {
		return nil, err
	}
	return &key.PublicKey, nil
}

type EmptyKeystore struct {
}

func (e EmptyKeystore) PrivateKey(kid string) (*rsa.PrivateKey, error) {
	return nil, fmt.Errorf("key not found")
}

func TestJWT(t *testing.T) {
	t.Run("Token should be composed by three chunks, separated by dot", func(t *testing.T) {
		token, err := jwt.JWT{}.Encode(nil)
		assert.NilError(t, err)
		chunks := strings.Split(token, ".")

		got := len(chunks)
		want := 3
		if got != want {
			t.Errorf("want: %d, got: %d", want, got)
		}
	})

	t.Run("encode + decode should return same jwt-body fields", func(t *testing.T) {
		token, err := jwt.JWT{
			Body: jwt.JWTBody{
				"iss": "myself",
			},
		}.Encode(nil)
		assert.NilError(t, err)
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

func TestValidateJWT(t *testing.T) {
	mks := &TestMemoryKeystore{}

	t.Run("token with 'none' as algorithm should be treated as invalid", func(t *testing.T) {
		token := jwt.JWT{
			Head:      &jwt.JWTHead{Alg: "none"},
			Body:      jwt.JWTBody{},
			Signature: "",
		}
		if err := token.Verify(nil); err == nil {
			t.Errorf("expected error, got %v", err)
		}
	})

	t.Run("invlid signatures should return errors", func(t *testing.T) {
		token := jwt.JWT{
			Head: &jwt.JWTHead{
				Alg: "RS256",
				Typ: "JWT",
			},
			Body: jwt.JWTBody{
				"name":  "John Doe",
				"admin": true,
			},
			Signature: "IpdRorSpAVgFG-T1IC_FnGzNHODaUdiQ3QdwYeQwBGVMkUYJ5jvWopOaqCSIFmM483lyDUrpg1wQ9Si1nj0dG-1NXrjjavAguWHBIMUvgYs0Lq0WKYAjkGMFk_XSxG9r6c8nmiNPtfCptRWQhI3M0dc5EPMiZOL2Ttg5y2e7OWBGP4EZHwLFYDCpp3CBz-iFMErACWsCJ-1HvYHYAVmPLZ8yrFK_uemjoluoHY1onH6jxoeinW91WP4ONuu5VBvpAMYjWqPeAeEBSqlfuiPNvYEz7CZroHzwdIoRKqcsCSOSp5la270LFsierdioqrcMFU6GhgwXVPx0ygNG5suyXQ",
		}

		if err := token.Verify(mks); err == nil {
			t.Errorf("Expected error, got %v", err)
		}
	})

	t.Run("should verify token with RS256 signature", func(t *testing.T) {
		token := jwt.JWT{
			Head: &jwt.JWTHead{
				Alg: "RS256",
				Typ: "JWT",
			},
			Body: jwt.JWTBody{
				"name":  "John Doe",
				"admin": true,
			},
			Signature: "IpdRorSpAVgFG-T0IC_FnGzNHODaUdiQ3QdwYeQwBGVMkUYJ5jvWopOaqCSIFmM483lyDUrpg1wQ9Si1nj0dG-1NXrjjavAguWHBIMUvgYs0Lq0WKYAjkGMFk_XSxG9r6c8nmiNPtfCptRWQhI3M0dc5EPMiZOL2Ttg5y2e7OWBGP4EZHwLFYDCpp3CBz-iFMErACWsCJ-1HvYHYAVmPLZ8yrFK_uemjoluoHY1onH6jxoeinW91WP4ONuu5VBvpAMYjWqPeAeEBSqlfuiPNvYEz7CZroHzwdIoRKqcsCSOSp5la270LFsierdioqrcMFU6GhgwXVPx0ygNG5suyXQ",
		}

		if err := token.Verify(mks); err != nil {
			t.Errorf("Error on token.Verify: %v", err)
		}
	})

	t.Run("sha signature should be deterministic", func(t *testing.T) {
		token := jwt.JWT{
			Head: &jwt.JWTHead{
				Alg: "RS256",
				Typ: "JWT",
			},
			Body: jwt.JWTBody{
				"name":  "John Doe",
				"admin": true,
			},
		}

		got, err := token.Sign(mks)
		want := "IpdRorSpAVgFG-T0IC_FnGzNHODaUdiQ3QdwYeQwBGVMkUYJ5jvWopOaqCSIFmM483lyDUrpg1wQ9Si1nj0dG-1NXrjjavAguWHBIMUvgYs0Lq0WKYAjkGMFk_XSxG9r6c8nmiNPtfCptRWQhI3M0dc5EPMiZOL2Ttg5y2e7OWBGP4EZHwLFYDCpp3CBz-iFMErACWsCJ-1HvYHYAVmPLZ8yrFK_uemjoluoHY1onH6jxoeinW91WP4ONuu5VBvpAMYjWqPeAeEBSqlfuiPNvYEz7CZroHzwdIoRKqcsCSOSp5la270LFsierdioqrcMFU6GhgwXVPx0ygNG5suyXQ"

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if got != want {
			t.Errorf("want: %q, got: %q", want, got)
		}
	})

	t.Run("should return error if unable to fetch private key", func(t *testing.T) {
		token := jwt.JWT{}

		emptyKS := EmptyKeystore{}
		_, err := token.Sign(emptyKS)
		assert.NilError(t, err)
	})

	t.Run("encoded tokens should end with a signature", func(t *testing.T) {
		token := jwt.JWT{
			Head: &jwt.JWTHead{Alg: "RS256", Typ: "JWT"},
			Body: jwt.JWTBody{},
		}
		sig, err := token.Sign(mks)
		if err != nil {
			t.Errorf("Unexpected error %v", err)
		}
		jwtStr, err := token.Encode(mks)
		assert.NilError(t, err)
		encoded_sign := strings.Split(jwtStr, ".")[2]

		if sig != encoded_sign {
			t.Errorf("want %q, got %q", sig, encoded_sign)
		}
	})

	t.Run("key id should be included optionally in jwt headers", func(t *testing.T) {
		token, err := jwt.JWT{
			Head: &jwt.JWTHead{Alg: "HS256", Typ: "JWT", Kid: "asdf"},
			Body: jwt.JWTBody{},
		}.Encode(mks)
		assert.NilError(t, err)

		decoded, err := jwt.Decode(token)
		assert.NilError(t, err)
		assert.Check(t, decoded.Head.Kid == "asdf")
	})
	t.Run("encoded token should be verifiable", func(t *testing.T) {
		jwtData, err := jwt.JWT{
			Head: &jwt.JWTHead{
				Alg: "HS256",
				Typ: "JWT",
				Kid: "asdf",
			},
			Body: jwt.JWTBody{},
		}.Encode(mks)
		assert.NilError(t, err)

		decoded, err := jwt.Decode(jwtData)
		assert.NilError(t, err)

		err = decoded.Verify(mks)
		assert.NilError(t, err)
	})

	t.Run("tokens should be signed using correct key ids", func(t *testing.T) {
		ks, err := keystore.NewTempKeystore()
		assert.NilError(t, err)

		info, err := ks.GetSigningKey("HS256")
		assert.NilError(t, err)

		jwtData, err := jwt.JWT{
			Head: &jwt.JWTHead{
				Alg: "HS256",
				Typ: "JWT",
				Kid: info.KeyID,
			},
			Body: jwt.JWTBody{},
		}.Encode(ks)
		assert.NilError(t, err)
		t.Logf("Token: %v", jwtData)

		decoded, err := jwt.Decode(jwtData)
		t.Logf("Signature: %v", decoded.Signature)
		assert.NilError(t, err)

		err = decoded.Verify(ks)
		assert.NilError(t, err)
	})
}
