package handlers_test

import (
	"github.com/ale-cci/oauthsrv/pkg/handlers"
	"gotest.tools/assert"
	"log"
	"net/http"
	"net/url"
	"testing"
)

func TestHandleAuthPassword(t *testing.T) {
	cnf, _ := handlers.EnvConfig()
	srv := NewTestServer(cnf)
	defer srv.Close()

	client := NoFollowRedirectClient(srv)
	requestPath := "/oauth/v2/auth?grant_type=password"

	t.Run("only post request should be allowed", func(t *testing.T) {
		resp, err := client.Get(srv.URL + requestPath)
		if err != nil {
			log.Fatalf("Unexpected error: %v", err)
		}

		assert.Equal(t, resp.StatusCode, http.StatusMethodNotAllowed)

	})
	t.Run("incorrect credentials should return 401", func(t *testing.T) {
		resp, err := client.PostForm(srv.URL+requestPath, url.Values{
			"username": {"wrong@email.com"},
			"password": {"root"},
		})

		if err != nil {
			log.Fatalf("Unexpected error: %v", err)
		}

		assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
	})
}
