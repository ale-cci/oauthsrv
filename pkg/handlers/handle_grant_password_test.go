package handlers_test

import (
	"github.com/ale-cci/oauthsrv/pkg/handlers"
	"gotest.tools/assert"
	"log"
	"net/http"
	"testing"
)

func TestHandleAuthPassword(t *testing.T) {
	cnf, _ := handlers.EnvConfig()
	srv := NewTestServer(cnf)
	defer srv.Close()

	client := NoFollowRedirectClient(srv)
	requestPath := "/oauth/v2/auth?grant_type=password"

	t.Run("should return 401 if user is not registered", func(t *testing.T) {
		resp, err := client.Get(srv.URL + requestPath)
		if err != nil {
			log.Fatalf("Unexpected error: %v", err)
		}

		assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)

	})
}
