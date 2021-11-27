package handlers_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ale-cci/oauthsrv/pkg/handlers"
	"github.com/ale-cci/oauthsrv/pkg/jwt"
	"gotest.tools/assert"
)

func TestHealthcheck(t *testing.T) {
	t.Run("/healthcheck should respond with 200", func(t *testing.T) {
		router := http.NewServeMux()
		cnf, _ := handlers.EnvConfig()
		handlers.AddRoutes(cnf, router)
		srv := httptest.NewServer(router)
		defer srv.Close()

		resp, err := srv.Client().Get(srv.URL + "/healthcheck")
		got := resp.StatusCode
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		want := 200
		if got != want {
			t.Errorf("want: %q, got: %q", want, got)
		}
	})

	t.Run("/healthcheck should return 500 if database connection is not valid", func(t *testing.T) {
		router := http.NewServeMux()
		cnf, _ := handlers.EnvConfig()
		handlers.AddRoutes(cnf, router)
		srv := httptest.NewServer(router)
		defer srv.Close()

		cnf.Database.Client().Disconnect(context.TODO())
		resp, err := srv.Client().Get(srv.URL + "/healthcheck")
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		got := resp.StatusCode
		want := 500
		if got != want {
			t.Errorf("want: %d, got: %d", want, got)
		}
	})
}

func TestRoutedFunctions(t *testing.T) {
	router := http.NewServeMux()
	cnf, _ := handlers.EnvConfig()
	handlers.AddRoutes(cnf, router)
	srv := httptest.NewServer(router)
	defer srv.Close()

	client := srv.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	tt := []struct {
		Endpoint string
		Status   int
	}{
		{"/oauth/v2/auth?grant_type=code", 302},
		{"/login", 200},
	}

	for i, tc := range tt {
		name := fmt.Sprintf("[%d] GET %s should return %d", i, tc.Endpoint, tc.Status)

		t.Run(name, func(t *testing.T) {
			resp, err := client.Get(srv.URL + tc.Endpoint)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			got := resp.StatusCode
			want := tc.Status
			if got != want {
				t.Errorf("want: %d, got %d", want, got)
			}
		})
	}
}
func TestTokenAuthorize(t *testing.T) {
	router := http.NewServeMux()
	cnf, _ := handlers.EnvConfig()

	scopeChecker := func(jwtBody jwt.JWTBody) error {
		if _, ok := jwtBody["custom_field"]; !ok {
			return fmt.Errorf("Missing custom_field")
		} else {
			return nil
		}
	}

	router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		handlers.CheckJWT(
			func(cnf *handlers.Config, w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("ok!"))
			},
			scopeChecker,
		)(cnf, w, r)
	})

	handlers.AddRoutes(cnf, router)
	srv := httptest.NewServer(router)
	defer srv.Close()

	client := srv.Client()

	t.Run("should return 400 if Authorization header is not provided", func(t *testing.T) {
		resp, err := client.Post(srv.URL+"/test", "application/json", bytes.NewReader([]byte{}))
		assert.NilError(t, err)

		assert.Check(t, resp.StatusCode == http.StatusBadRequest, fmt.Sprintf("[resp.StatusCode is %v]", resp.StatusCode))

		authHeader := resp.Header.Get("www-authenticate")
		t.Logf("List of headers: %q", resp.Header)
		assert.Check(
			t,
			authHeader == "Bearer error=\"invalid_request\"",
			fmt.Sprintf("[header is %q]", authHeader),
		)
	})

	t.Run("should return 401 if token is malformed", func(t *testing.T) {
		req, err := http.NewRequest("POST", srv.URL+"/test", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", "a.b.c"))
		assert.NilError(t, err)

		resp, err := client.Do(req)
		assert.NilError(t, err)
		assert.Check(t, resp.StatusCode == http.StatusUnauthorized, fmt.Sprintf("[resp.StatusCode is %v]", resp.StatusCode))

		authenticateHeader := resp.Header.Get("www-authenticate")
		assert.Check(t, authenticateHeader == "Bearer error=\"invalid_token\"")
	})

	t.Run("should call wrapped endpoint on valid jwt", func(t *testing.T) {
		req, err := http.NewRequest("POST", srv.URL+"/test", nil)
		assert.NilError(t, err)

		encodedJWT, err := jwt.NewJWT(cnf.Keystore, jwt.JWTBody{
			"custom_field": true,
		})
		assert.NilError(t, err)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", encodedJWT))

		resp, err := client.Do(req)
		assert.NilError(t, err)
		assert.Check(t, resp.StatusCode == http.StatusOK, fmt.Sprintf("[status is %v]", resp.StatusCode))
		body, err := io.ReadAll(resp.Body)
		assert.NilError(t, err)
		assert.Check(t, string(body) == "ok!")
	})

	t.Run("should return 403 without calling the handler if scopeChecker returns an error", func(t *testing.T) {
		req, err := http.NewRequest("POST", srv.URL+"/test", nil)
		assert.NilError(t, err)

		encodedJWT, err := jwt.NewJWT(cnf.Keystore, jwt.JWTBody{})
		assert.NilError(t, err)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", encodedJWT))

		resp, err := client.Do(req)
		assert.NilError(t, err)
		assert.Check(t, resp.StatusCode == http.StatusForbidden, fmt.Sprintf("[status is %v]", resp.StatusCode))
		body, err := io.ReadAll(resp.Body)
		assert.NilError(t, err)
		assert.Check(t, string(body) != "ok!")

		authenticateHeader := resp.Header.Get("www-authenticate")
		assert.Check(t, authenticateHeader == "Bearer error=\"insufficient_scope\"")
	})

	t.Run("should return 401 if token is not valid", func(t *testing.T) {
		req, err := http.NewRequest("POST", srv.URL+"/test", nil)
		assert.NilError(t, err)

		encodedJWT, err := jwt.JWT{
			Head: &jwt.JWTHead{
				Alg: "none",
			},
			Body: jwt.JWTBody{
				"exp":          time.Now().Unix() + 3600,
				"custom_field": true,
			},
		}.Encode(nil)

		assert.NilError(t, err)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", encodedJWT))
		assert.NilError(t, err)

		resp, err := client.Do(req)
		assert.NilError(t, err)
		assert.Check(t, resp.StatusCode == http.StatusUnauthorized, fmt.Sprintf("[resp.StatusCode is %v]", resp.StatusCode))

		authenticateHeader := resp.Header.Get("www-authenticate")
		assert.Check(t, authenticateHeader == "Bearer error=\"invalid_token\"")
	})
}
