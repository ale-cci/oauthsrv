package handlers_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"github.com/ale-cci/oauthsrv/pkg/handlers"
	"github.com/ale-cci/oauthsrv/pkg/jwt"
	"github.com/ale-cci/oauthsrv/pkg/passwords"
	"go.mongodb.org/mongo-driver/bson"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"io/ioutil"
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

	err := initApps(cnf)
	t.Cleanup(deinitApps(cnf))

	assert.Assert(t, is.Nil(err))

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
		assert.NilError(t, err)
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		body, err := ioutil.ReadAll(resp.Body)
		assert.NilError(t, err)
		var jsonBody struct {
			Jwt string `json:"jwt"`
		}
		err = json.Unmarshal(body, &jsonBody)
		assert.NilError(t, err)

		t.Run("jwt is valid", func(t *testing.T) {
			t.Logf("Value of jwt: %q", jsonBody.Jwt)
			jwt, err := jwt.Decode(jsonBody.Jwt)
			assert.NilError(t, err)

			t.Run("should contain valid head claims", func(t *testing.T) {
				assert.Equal(t, jwt.Head.Typ, "JWT")
				assert.Equal(t, jwt.Head.Alg, "none")
			})
			t.Run("should contain valid body claims", func(t *testing.T) {
				assert.Equal(t, jwt.Body["sub"], "client-id")
			})
		})

	})
}

func initApps(cnf *handlers.Config) error {
	pass, err := passwords.New(rand.Reader, "client-secret")
	cnf.Database.Collection("apps").InsertOne(context.Background(), bson.D{
		{Key: "_id", Value: "client-id"},
		{Key: "client_secret", Value: pass},
	})
	return err
}

func deinitApps(cnf *handlers.Config) func() {
	return func() {
		cnf.Database.Collection("apps").Drop(context.Background())
	}
}
