package handlers_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ale-cci/oauthsrv/pkg/handlers"
	"github.com/ale-cci/oauthsrv/pkg/jwt"
	"github.com/ale-cci/oauthsrv/pkg/mux"
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
	client := srv.Client()

	cnf.Database.Collection("identities").InsertMany(
		context.Background(),
		[]interface{}{
			bson.D{
				{Key: "_id", Value: "the-first-user"},
			},
			bson.D{
				{Key: "_id", Value: "the-second-user"},
				{Key: "groups", Value: []string{"app1:view", "app-2:read", "app-3:admin"}},
			},
			bson.D{
				{Key: "_id", Value: "admin-user"},
				{Key: "groups", Value: []string{"admin"}},
			},
			bson.D{
				{Key: "_id", Value: "the-manager"},
				{Key: "groups", Value: []string{"manager"}},
			},
			bson.D{
				{Key: "_id", Value: "the-app1-admin"},
				{Key: "groups", Value: []string{"app1:admin"}},
			},
			bson.D{
				{Key: "_id", Value: "the-app2-manager"},
				{Key: "groups", Value: []string{"app-2:manager"}},
			},
		},
	)

	t.Run("endpoint should exist", func(t *testing.T) {
		resp, err := client.Get(srv.URL + "/api/users/the-first-user/groups")
		assert.NilError(t, err)
		assert.Equal(t, resp.StatusCode, http.StatusBadRequest)

		auth := resp.Header.Get("www-authenticate")
		assert.Check(t, auth != "")
	})

	token1, err := jwt.NewJWT(cnf.Keystore, jwt.JWTBody{"sub": "the-first-user"})
	assert.NilError(t, err)

	t.Run("owner should be able to check it's groups", func(t *testing.T) {
		req, err := http.NewRequest("GET", srv.URL+"/api/users/the-first-user/groups", nil)
		assert.NilError(t, err)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token1))

		resp, err := client.Do(req)
		assert.NilError(t, err)
		assert.Equal(t, resp.StatusCode, http.StatusOK)

		t.Run("response contains groups in json format", func(t *testing.T) {
			assert.Equal(t, resp.Header.Get("content-type"), "application/json")
			var response struct {
				Data struct {
					Groups []string `json:"groups"`
				} `json:"data"`
			}

			body, err := io.ReadAll(resp.Body)
			assert.NilError(t, err)

			err = json.Unmarshal(body, &response)
			assert.NilError(t, err)

			assert.DeepEqual(t, response.Data.Groups, []string{})
		})
	})

	t.Run("should return 403 if sub is not provided", func(t *testing.T) {
		req, err := http.NewRequest("GET", srv.URL+"/api/users/the-first-user/groups", nil)
		assert.NilError(t, err)
		token, err := jwt.NewJWT(cnf.Keystore, jwt.JWTBody{})
		assert.NilError(t, err)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

		resp, err := client.Do(req)
		assert.NilError(t, err)
		assert.Equal(t, resp.StatusCode, http.StatusForbidden)
	})

	t.Run("users without any permissions should not be able to retrieve user groups", func(t *testing.T) {
		req, err := http.NewRequest("GET", srv.URL+"/api/users/the-second-user/groups", nil)
		assert.NilError(t, err)
		token2, err := jwt.NewJWT(cnf.Keystore, jwt.JWTBody{"sub": "the-first-user"})
		assert.NilError(t, err)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token2))

		resp, err := client.Do(req)
		assert.NilError(t, err)
		assert.Equal(t, resp.StatusCode, http.StatusForbidden)

		t.Run("data should not be contained in json response", func(t *testing.T) {
			assert.Equal(t, resp.Header.Get("content-type"), "application/json")
			var response map[string]interface{}

			body, err := io.ReadAll(resp.Body)
			assert.NilError(t, err)

			err = json.Unmarshal(body, &response)

			_, contained := response["data"]
			assert.Check(t, contained == false, "`data` should not be contained in json response")

			msg, ok := response["message"]
			assert.Assert(t, ok, "`message` should be contained in json response")
			assert.Assert(t, msg != "", "`message` should not be empty")
		})
	})

	t.Run("returns list of groups if user performing the request is manager", func(t *testing.T) {
		tt := []struct {
			TcName      string
			GetGroupsOf string
			Sub         string
			ViewsGroups []string
		}{
			{
				TcName:      "group's owner can view his groups",
				Sub:         "the-second-user",
				GetGroupsOf: "the-second-user",
				ViewsGroups: []string{"app1:view", "app-2:read", "app-3:admin"},
			},
			{
				TcName:      "managers can view all groups",
				Sub:         "the-manager",
				GetGroupsOf: "the-second-user",
				ViewsGroups: []string{"app1:view", "app-2:read", "app-3:admin"},
			},
			{
				TcName:      "admin can view all groups",
				Sub:         "admin-user",
				GetGroupsOf: "the-second-user",
				ViewsGroups: []string{"app1:view", "app-2:read", "app-3:admin"},
			},
			{
				TcName:      "app admins can only view it's app groups",
				Sub:         "the-app1-admin",
				GetGroupsOf: "the-second-user",
				ViewsGroups: []string{"app1:view"},
			},
			{
				TcName:      "app managers can only view it's app groups",
				Sub:         "the-app2-manager",
				GetGroupsOf: "the-second-user",
				ViewsGroups: []string{"app-2:read"},
			},
			{
				TcName:      "user without permissions should not see other's groups",
				Sub:         "the-second-user",
				GetGroupsOf: "the-first-user",
				ViewsGroups: []string{},
			},
		}

		for id, tc := range tt {
			t.Run(fmt.Sprintf("[%d] %s", id, tc.TcName), func(t *testing.T) {
				req, err := http.NewRequest("GET", srv.URL+"/api/users/"+tc.GetGroupsOf+"/groups", nil)
				assert.NilError(t, err)

				token, err := jwt.NewJWT(cnf.Keystore, jwt.JWTBody{
					"sub": tc.Sub,
				})
				assert.NilError(t, err)
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

				resp, err := client.Do(req)
				assert.NilError(t, err)
				assert.Equal(t, resp.StatusCode, http.StatusOK)

				var response struct {
					Data struct {
						Groups []string `json:"groups"`
					} `json:"data"`
				}
				body, err := io.ReadAll(resp.Body)
				assert.NilError(t, err)

				err = json.Unmarshal(body, &response)
				assert.NilError(t, err)

				assert.DeepEqual(t, response.Data.Groups, tc.ViewsGroups)
			})
		}
	})
}
