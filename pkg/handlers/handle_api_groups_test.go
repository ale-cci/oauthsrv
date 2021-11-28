package handlers_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ale-cci/oauthsrv/pkg/handlers"
	"github.com/ale-cci/oauthsrv/pkg/jwt"
	"github.com/ale-cci/oauthsrv/pkg/mux"
	"github.com/ale-cci/oauthsrv/pkg/passwords"
	"go.mongodb.org/mongo-driver/bson"
	"gotest.tools/assert"
)

func TestHandleGroupsApi(t *testing.T) {
	router := mux.NewServeMux()
	cnf, err := handlers.EnvConfig()
	assert.NilError(t, err)
	handlers.AddRoutes(cnf, router)
	srv := httptest.NewServer(router)
	defer srv.Close()

	cnf.Database.Collection("identities").Drop(context.Background())
	passwd, _ := passwords.New(rand.Reader, "password")

	client := srv.Client()

	cnf.Database.Collection("identities").InsertMany(
		context.Background(),
		[]interface{}{
			bson.D{
				{Key: "_id", Value: "the-first-user"},
				{Key: "email", Value: "test@email.com"},
				{Key: "password", Value: passwd},
			},
			bson.D{
				{Key: "_id", Value: "the-second-user"},
				{Key: "email", Value: "another@email.com"},
				{Key: "password", Value: passwd},
			},
		},
	)

	t.Run("endpoint should exist", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/users/1/groups")
		assert.NilError(t, err)
		assert.Equal(t, resp.StatusCode, http.StatusBadRequest)

		auth := resp.Header.Get("www-authenticate")
		assert.Check(t, auth != "")
	})

	token1, err := jwt.NewJWT(cnf.Keystore, jwt.JWTBody{"sub": "the-first-user"})
	assert.NilError(t, err)

	t.Run("owner should be able to check it's groups", func(t *testing.T) {
		req, err := http.NewRequest("GET", srv.URL+"/api/users/1/groups", nil)
		assert.NilError(t, err)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token1))

		resp, err := client.Do(req)
		assert.NilError(t, err)
		assert.Equal(t, resp.StatusCode, http.StatusOK)
	})
}
