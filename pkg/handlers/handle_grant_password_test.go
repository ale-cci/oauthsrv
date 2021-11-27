package handlers_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/ale-cci/oauthsrv/pkg/handlers"
	"github.com/ale-cci/oauthsrv/pkg/jwt"
	"github.com/ale-cci/oauthsrv/pkg/passwords"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gotest.tools/assert"
)

func TestHandleAuthPassword(t *testing.T) {
	cnf, _ := handlers.EnvConfig()
	srv := NewTestServer(cnf)
	defer srv.Close()

	client := NoFollowRedirectClient(srv)
	requestPath := "/oauth/v2/auth?grant_type=password"

	password, _ := passwords.New(rand.Reader, "test")
	_, err := cnf.Database.Collection("identities").UpdateOne(
		context.Background(),
		bson.D{
			{Key: "_id", Value: "unique-user-identifier"},
			{Key: "email", Value: "test-grant-password@email.com"},
		},
		bson.D{{"$set", bson.D{{"password", password}}}},
		options.Update().SetUpsert(true),
	)
	assert.NilError(t, err)

	t.Run("only post request should be allowed", func(t *testing.T) {
		resp, err := client.Get(srv.URL + requestPath)
		assert.NilError(t, err)
		assert.Equal(t, resp.StatusCode, http.StatusMethodNotAllowed)

		t.Run("response should be a valid json", func(t *testing.T) {
			data, err := io.ReadAll(resp.Body)
			assert.NilError(t, err)

			var fields map[string]string
			err = json.Unmarshal(data, &fields)
			assert.NilError(t, err)
		})
	})

	t.Run("incorrect credentials should return 401", func(t *testing.T) {
		resp, err := client.PostForm(srv.URL+requestPath, url.Values{
			"username": {"test-grant-password@email.com"},
			"password": {"wrong-password"},
		})

		assert.NilError(t, err)
		assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)

		t.Run("response should be a valid json", func(t *testing.T) {
			data, err := io.ReadAll(resp.Body)
			assert.NilError(t, err)

			var fields map[string]string
			err = json.Unmarshal(data, &fields)
			assert.NilError(t, err)
		})
	})

	t.Run("correct credentials should return jwt", func(t *testing.T) {
		// add user to db
		resp, err := client.PostForm(srv.URL+requestPath, url.Values{
			"username": {"test-grant-password@email.com"},
			"password": {"test"},
		})
		assert.NilError(t, err)

		body, err := io.ReadAll(resp.Body)
		assert.NilError(t, err)

		var fields map[string]string
		err = json.Unmarshal(body, &fields)
		assert.NilError(t, err)
		assert.Equal(t, resp.StatusCode, http.StatusOK, fields["message"])

		jwtData, err := jwt.Decode(fields["access_token"])
		assert.NilError(t, err)

		assert.Check(t, jwtData.Head.Alg == "HS256")

		err = jwtData.Verify(cnf.Keystore)
		assert.NilError(t, err)

		t.Run("jwt has valid exp date", func(t *testing.T) {
			exp, ok := jwtData.Body["exp"]
			assert.Assert(t, ok, "Provided jwt doesn't have exp field")

			expValue, err := exp.(json.Number).Int64()
			assert.NilError(t, err)
			assert.Check(t, expValue > time.Now().Unix(), fmt.Sprintf("[exp is %v]", expValue))
		})

		t.Run("jwt has valid iat field", func(t *testing.T) {
			iat, ok := jwtData.Body["iat"]
			assert.Assert(t, ok, "Provided jwt doesn't have iat field")

			iatValue, err := iat.(json.Number).Int64()
			assert.NilError(t, err)
			assert.Check(t, iatValue <= time.Now().Unix(), fmt.Sprintf("[iat is %v]", iatValue))
		})

		t.Run("jwt has correct sub value", func(t *testing.T) {
			sub, ok := jwtData.Body["sub"]
			assert.Assert(t, ok, "Provided jwt doesn't have sub field")

			assert.Equal(t, sub, "unique-user-identifier")
		})
	})
}
