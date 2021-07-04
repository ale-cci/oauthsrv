package handlers_test

import (
	"context"
	"fmt"
	"github.com/ale-cci/oauthsrv/handlers"
	"go.mongodb.org/mongo-driver/bson"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)


func TestPost_HandlerLogin(t *testing.T) {
	router := http.NewServeMux()
	cnf, _ := handlers.EnvConfig()
	handlers.AddRoutes(cnf, router)
	srv := httptest.NewServer(router)
	defer srv.Close()

	client := srv.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	cnf.Database.Collection("identities").InsertOne(context.Background(), bson.D{
		{Key: "email", Value: "test@email.com"},
		{Key: "password", Value: "password"},
	})

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
}
