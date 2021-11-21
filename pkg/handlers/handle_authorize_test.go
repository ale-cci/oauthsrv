package handlers_test

import (
	"bufio"
	"bytes"
	"github.com/ale-cci/oauthsrv/pkg/handlers"
	"github.com/ale-cci/oauthsrv/pkg/jwt"
	"github.com/kylelemons/godebug/diff"
	"gotest.tools/assert"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
)

func TestAuthorizeFromGuest(t *testing.T) {
	cnf, _ := handlers.EnvConfig()
	srv := NewTestServer(cnf)
	defer srv.Close()

	client := NoFollowRedirectClient(srv)
	requestPath := "/oauth/v2/auth?grant_type=code"

	t.Run("should redirect to login if user is not authorized", func(t *testing.T) {
		resp, err := client.Get(srv.URL + requestPath)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
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

	t.Run("should redirect to login if user has invalid sid", func(t *testing.T) {
		authCookie := &http.Cookie{Name: "sid", Value: "a.b.c"}
		location, _ := url.Parse(srv.URL)
		client.Jar, _ = cookiejar.New(nil)
		client.Jar.SetCookies(location, []*http.Cookie{authCookie})
		resp, err := client.Get(srv.URL + requestPath)

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		redirectURL, err := resp.Location()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		got := redirectURL.RequestURI()

		query := url.QueryEscape(requestPath)
		want := "/login?continue=" + query
		if got != want {
			t.Fatalf("want: %q, got: %q", want, got)
		}
	})
}

func TestAuthorizeEndpoint(t *testing.T) {
	cnf, _ := handlers.EnvConfig()
	srv := NewTestServer(cnf)
	defer srv.Close()

	client := NoFollowRedirectClient(srv)

	authToken, err := jwt.JWT{
		Head: &jwt.JWTHead{
			Alg: "none",
		},
		Body: jwt.JWTBody{
			"sid":   1,
			"email": "test@email.com",
		},
	}.Encode(nil)
	assert.NilError(t, err)

	authCookie := &http.Cookie{Name: "sid", Value: authToken}
	location, _ := url.Parse(srv.URL)
	client.Jar, _ = cookiejar.New(nil)
	client.Jar.SetCookies(location, []*http.Cookie{authCookie})

	t.Run("should return 200 if user is authenticated", func(t *testing.T) {
		requestPath := "/oauth/v2/auth?" + url.Values{
			"client_id":    {"something"},
			"redirect_uri": {""},
			"grant_type":   {"code"},
			"scope":        {""},
		}.Encode()

		resp, err := client.Get(srv.URL + requestPath)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		got := resp.StatusCode
		want := http.StatusOK
		if got != want {
			t.Errorf("want: %d, got: %d", want, got)
		}
	})

	t.Run("should return 400 if not all arguments were provided", func(t *testing.T) {
		requestPath := "/oauth/v2/auth?" + url.Values{
			"redirect_uri": {""},
			"grant_type":   {"code"},
			"scope":        {""},
		}.Encode()

		resp, err := client.Get(srv.URL + requestPath)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		got := resp.StatusCode
		want := http.StatusBadRequest
		if got != want {
			t.Errorf("want: %d, got: %d", want, got)
		}
	})

	t.Run("should render authorize page on success", func(t *testing.T) {
		tmpl, err := template.ParseFiles("templates/authorize.tmpl")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		var want bytes.Buffer
		buf := bufio.NewWriter(&want)

		if err := tmpl.Execute(buf, nil); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		buf.Flush()

		requestPath := "/oauth/v2/auth?" + url.Values{
			"client_id":  {"-"},
			"grant_type": {"code"},
		}.Encode()
		resp, err := client.Get(srv.URL + requestPath)

		got, err := ioutil.ReadAll(resp.Body)

		strGot := string(got)
		strWant := string(want.Bytes())

		if strGot != strWant {
			t.Errorf(diff.Diff(strWant, strGot))
		}
	})

	t.Run("should return 400 if grant type is not registered", func(t *testing.T) {
		reqPath := "/oauth/v2/auth?" + url.Values{
			"grant_type": {"random"},
		}.Encode()

		resp, err := client.PostForm(srv.URL+reqPath, url.Values{})
		assert.NilError(t, err)
		assert.Equal(t, resp.StatusCode, http.StatusBadRequest)
	})
}
