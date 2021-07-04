package handlers_test

import (
	"context"
	"github.com/ale-cci/oauthsrv/handlers"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
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

	tt := []struct{
		Endpoint string
		Status int
	}{
		{"/oauth/v2/auth", 302},
		{"/login", 200},
	}

	for i, tc := range tt {
		name := fmt.Sprintf("[%d] GET %s should retur %d", i, tc.Endpoint, tc.Status)

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
