package handlers_test

import (
	"context"
	"github.com/ale-cci/oauthsrv/pkg/handlers"
	"go.mongodb.org/mongo-driver/bson"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"net/http"
	"net/url"
	"testing"
)

func TestClientCredentials(t *testing.T) {
	// Create new testing context
	cnf, _ := handlers.EnvConfig()
	srv := NewTestServer(cnf)
	defer srv.Close()

	// TODO: create client application
	client := srv.Client()
	cnf.Database.Collection("apps").InsertOne(context.Background(), bson.D{
		{Key: "_id", Value: "client-id"},
		{Key: "secret", Value: "client-secret"},
	})

	urlPath := srv.URL + "/oauth/v2/auth" + "?" + url.Values{
		"grant_type": {"client_credentials"},
	}.Encode()

	t.Run("should return method not allowed for get requests", func(t *testing.T) {
		resp, err := client.Get(urlPath)

		assert.Assert(t, is.Nil(err))

		expect := http.StatusMethodNotAllowed
		got := resp.StatusCode

		assert.Equal(t, expect, got)
	})

	t.Run("should return 401 if credentials are wrong", func(t *testing.T) {
		resp, err := client.PostForm(urlPath, url.Values{
			"client_id":     {"test"},
			"client_secret": {"test"},
		})
		assert.Assert(t, is.Nil(err))

		expect := http.StatusUnauthorized
		got := resp.StatusCode

		assert.Equal(t, expect, got)
	})
}
