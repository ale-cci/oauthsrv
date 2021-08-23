package handlers_test

import (
	"net/http/cookiejar"
	"net/url"
	"testing"

	"github.com/ale-cci/oauthsrv/pkg/handlers"
)

func TestGrantTypeCode(t *testing.T) {
	cnf, _ := handlers.EnvConfig()
	srv := NewTestServer(cnf)
	defer srv.Close()

	client := srv.Client()
	client.Jar, _ = cookiejar.New(nil)

	// TODO: register client application
	const TEST_CLIENT_SECRET = ""
	const TEST_CLIENT_ID = ""

	t.Run("should return code token", func(t *testing.T) {
		q := url.Values{
			"client_id":     {TEST_CLIENT_ID},
			"client_secret": {TEST_CLIENT_SECRET},
		}
		resp, _ := client.Get(srv.URL + "/oauth/v2/auth?" + q.Encode())
		resp, _ = client.PostForm(resp.Request.URL.RequestURI(), url.Values{
			"username": {"test@email.com"},
			"password": {"password"},
		})
	})
}
