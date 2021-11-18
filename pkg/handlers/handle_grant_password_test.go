package handlers_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"testing"

	"github.com/ale-cci/oauthsrv/pkg/handlers"
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
		bson.D{{Key: "_id", Value: "test-grant-password@email.com"}},
		bson.D{{"$set", bson.D{{"password", password}}}},
		options.Update().SetUpsert(true),
	)
	if err != nil {
		log.Fatalf("Unepected error while inserting new user: %v", err)
	}

	t.Run("only post request should be allowed", func(t *testing.T) {
		resp, err := client.Get(srv.URL + requestPath)
		if err != nil {
			log.Fatalf("Unexpected error: %v", err)
		}

		assert.Equal(t, resp.StatusCode, http.StatusMethodNotAllowed)

		t.Run("response should be a valid json", func(t *testing.T) {
			data, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Fatalf("Unable to read response body: %v", err)
			}

			var fields map[string]string
			err = json.Unmarshal(data, &fields)
			if err != nil {
				log.Fatalf("Unable to decode json body: %v", err)
			}
		})

	})
	t.Run("incorrect credentials should return 401", func(t *testing.T) {
		resp, err := client.PostForm(srv.URL+requestPath, url.Values{
			"username": {"test-grant-password@email.com"},
			"password": {"wrong-password"},
		})

		if err != nil {
			log.Fatalf("Unexpected error: %v", err)
		}

		assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
		t.Run("response should be a valid json", func(t *testing.T) {
			data, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Fatalf("Unable to read response body: %v", err)
			}

			var fields map[string]string
			err = json.Unmarshal(data, &fields)
			if err != nil {
				log.Fatalf("Unable to decode json body: %v", err)
			}
		})
	})

	t.Run("correct credentials should return jwt", func(t *testing.T) {
		// add user to db
		resp, err := client.PostForm(srv.URL+requestPath, url.Values{
			"username": {"test-grant-password@email.com"},
			"password": {"test"},
		})
		if err != nil {
			log.Fatalf("Unexpected error: %v", err)
		}

		assert.Equal(t, resp.StatusCode, http.StatusOK)
	})

}