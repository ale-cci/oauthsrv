package handlers_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"github.com/ale-cci/oauthsrv/pkg/handlers"
	"github.com/ale-cci/oauthsrv/pkg/jwt"
	"github.com/ale-cci/oauthsrv/pkg/passwords"
	"github.com/kylelemons/godebug/diff"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/net/publicsuffix"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
)

func init() {
	// cd to root directory for templates importing
	if err := os.Chdir("../../"); err != nil {
		panic(err)
	}
}

func NewTestServer(cnf *handlers.Config) *httptest.Server {
	router := http.NewServeMux()
	if cnf == nil {
		cnf, _ = handlers.EnvConfig()
	}
	handlers.AddRoutes(cnf, router)
	srv := httptest.NewServer(router)
	return srv
}

func NoFollowRedirectClient(srv *httptest.Server) *http.Client {
	client := srv.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return client
}

func TestHandleLoginPost(t *testing.T) {
	cnf, _ := handlers.EnvConfig()
	srv := NewTestServer(cnf)
	defer srv.Close()
	client := NoFollowRedirectClient(srv)

	password, _ := passwords.New(rand.Reader, "password")
	cnf.Database.Collection("identities").InsertOne(context.Background(), bson.D{
		{Key: "_id", Value: "test@email.com"},
		{Key: "password", Value: password},
	})

	t.Run("should allow authentication only when username and password matches", func(t *testing.T) {
		tt := []struct {
			TestCaseName   string
			Username       string
			Password       string
			Continue       string
			ExpectStatus   int
			ExpectLocation string
		}{
			{
				TestCaseName:   "blank credentials should redirect to /login",
				Username:       "",
				Password:       "",
				Continue:       "/after-login",
				ExpectStatus:   http.StatusFound,
				ExpectLocation: "/login?continue=%2Fafter-login",
			},
			{
				TestCaseName:   "correct credentials should redirect to continue",
				Username:       "test@email.com",
				Password:       "password",
				Continue:       "/after-login",
				ExpectStatus:   http.StatusFound,
				ExpectLocation: "/after-login",
			},
			{
				TestCaseName:   "Wrong password should not allow login",
				Username:       "test@email.com",
				Password:       "pass",
				Continue:       "after",
				ExpectStatus:   http.StatusFound,
				ExpectLocation: "/login?continue=after",
			},
		}

		for i, tc := range tt {
			name := fmt.Sprintf("[%d] %s", i, tc.TestCaseName)

			t.Run(name, func(t *testing.T) {
				values := url.Values{
					"username": []string{tc.Username},
					"password": []string{tc.Password},
				}

				resp, err := client.PostForm(srv.URL+"/login?continue="+url.QueryEscape(tc.Continue), values)
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				gotStatus := resp.StatusCode
				wantStatus := tc.ExpectStatus

				if gotStatus != wantStatus {
					t.Fatalf("want status code: %d, got: %d", wantStatus, gotStatus)
				}

				var url *url.URL
				url, err = resp.Location()
				if err != nil {
					t.Errorf("Unexpected error on retrieving location: %v", err)
				}

				got := url.RequestURI()
				want := tc.ExpectLocation
				if got != want {
					t.Errorf("want: %q, got: %q", want, got)
				}
			})
		}
	})

	t.Run("should add cookie only if username and password matches", func(t *testing.T) {
		tt := []struct {
			TestCaseName       string
			Username, Password string
			ReturnsCookie      bool
		}{
			{
				"Should return cookie for authenticated user",
				"test@email.com", "password",
				true,
			},
			{
				"Should not return cookie if credentials are incorrect",
				"test@email.com", "a",
				false,
			},
		}

		for i, tc := range tt {
			name := fmt.Sprintf("[%d] %s", i, tc.TestCaseName)
			t.Run(name, func(t *testing.T) {

				values := url.Values{
					"username": []string{tc.Username},
					"password": []string{tc.Password},
				}

				resp, err := client.PostForm(srv.URL+"/login?continue=%2Ftest", values)
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				found := false
				for _, cookie := range resp.Cookies() {
					if cookie.Name == "sid" {
						found = true
						break
					}
				}

				if found != tc.ReturnsCookie {
					if tc.ReturnsCookie {
						t.Errorf("Response does not contain cookie with name 'sid'")
					} else {
						t.Errorf("Response should not contain cookie 'sid'")
					}
				}
			})
		}
	})

	t.Run("successful login should set a valid jwt", func(t *testing.T) {
		values := url.Values{
			"username": {"test@email.com"},
			"password": {"password"},
		}
		resp, err := client.PostForm(srv.URL+"/login?continue=%2Fx", values)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		var sid string
		for _, cookie := range resp.Cookies() {
			if cookie.Name == "sid" {
				sid = cookie.Value
				break
			}
		}

		_, err = jwt.Decode(sid)
		if err != nil {
			t.Fatalf("Invalid jwt: %q", sid)
		}
	})
}

func TestHandleLoginGet(t *testing.T) {
	cnf, _ := handlers.EnvConfig()
	srv := NewTestServer(cnf)
	defer srv.Close()

	client := NoFollowRedirectClient(srv)
	client.Jar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})

	t.Run("should redirect to continue if user has sid cookie", func(t *testing.T) {

		srvURL, _ := url.Parse(srv.URL)
		client.Jar.SetCookies(srvURL, []*http.Cookie{
			{Name: "sid", Value: "1"},
		})

		resp, err := client.Get(srv.URL + "/login?continue=%2Fcontinue")
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		respUrl, err := resp.Location()
		if err != nil {
			t.Errorf("Unexpected error while retrieving location: %v", err)
		}

		got := respUrl.RequestURI()
		want := "/continue"
		if got != want {
			t.Errorf("want: %q, got: %q", want, got)
		}
	})
}

func TestHandleLoginReturnsErrorMessage(t *testing.T) {
	cnf, _ := handlers.EnvConfig()
	srv := NewTestServer(cnf)
	defer srv.Close()

	client := srv.Client()
	client.Jar, _ = cookiejar.New(nil)

	password, _ := passwords.New(rand.Reader, "password")
	cnf.Database.Collection("identities").InsertOne(context.Background(), bson.D{
		{Key: "_id", Value: "test@email.com"},
		{Key: "password", Value: password},
	})

	t.Run("should print error message if credentials are not correct", func(t *testing.T) {
		resp, err := client.PostForm(srv.URL+"/login?continue=%2Fcontinue", url.Values{
			"username": {"test@email.com"},
			"password": {"err"},
		})

		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		data := struct{ Error string }{"Wrong username or password"}
		want, err := execTemplate("templates/login.tmpl", data)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		got, err := ioutil.ReadAll(resp.Body)

		assertStringEquals(t, string(want), string(got))
	})
}

func execTemplate(name string, data interface{}) ([]byte, error) {
	tmpl := template.Must(template.ParseFiles("templates/login.tmpl"))

	var body bytes.Buffer
	buf := bufio.NewWriter(&body)

	if err := tmpl.Execute(buf, data); err != nil {
		return nil, err
	}
	buf.Flush()
	return body.Bytes(), nil
}

func assertStringEquals(t *testing.T, want, got string) {
	if got != want {
		t.Errorf(diff.Diff(want, got))
	}
}
