package handlers_test

import (
	"context"
	"crypto/rand"
	"github.com/ale-cci/oauthsrv/pkg/handlers"
	"github.com/ale-cci/oauthsrv/pkg/passwords"
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

	pass, err := passwords.New(rand.Reader, "client-secret")
	assert.Assert(t, is.Nil(err))

	cnf.Database.Collection("apps").InsertOne(context.Background(), bson.D{
		{Key: "_id", Value: "client-id"},
		{Key: "secret", Value: pass},
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
			"client_id":     {"client-id"},
			"client_secret": {"test"},
		})
		assert.Assert(t, is.Nil(err))

		expect := http.StatusUnauthorized
		got := resp.StatusCode

		assert.Equal(t, expect, got)
	})

	t.Run("should return jwt if credentials are correct", func(t *testing.T) {
		resp, err := client.PostForm(urlPath, url.Values{
			"client_id":     {"client-id"},
			"client_secret": {"client-secret"},
		})
		assert.Assert(t, is.Nil(err))
		assert.Equal(t, resp.StatusCode, http.StatusOK)
	})
}
