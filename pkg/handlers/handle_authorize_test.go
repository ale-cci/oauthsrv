package handlers_test


import (
	"testing"
	"net/url"
	"github.com/ale-cci/oauthsrv/pkg/handlers"
)


func TestAuthorizeEndpoint(t *testing.T) {
	cnf, _ := handlers.EnvConfig()
	srv := NewTestServer(cnf)
	defer srv.Close()

	client := NoFollowRedirectClient(srv)

	t.Run("should redirect to login if user is not authorized", func(t *testing.T) {
		requestPath := "/oauth/v2/auth?client_id=a"
		resp, err := client.Get(srv.URL + requestPath)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		redirectURL, err := resp.Location()
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}


		got := redirectURL.RequestURI()

		query := url.QueryEscape(requestPath)
		want := "/login?continue=" + query

		if got != want {
			t.Errorf("want: %q, got: %q", want, got)
		}
	})
}
