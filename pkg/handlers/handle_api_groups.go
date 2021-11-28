package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ale-cci/oauthsrv/pkg/jwt"
	"github.com/ale-cci/oauthsrv/pkg/mux"
	"go.mongodb.org/mongo-driver/bson"
)

func handleGroups(cnf *Config, w http.ResponseWriter, r *http.Request) {
	handler := CheckJWT(handleGroupsGET, func(_ jwt.JWTBody) error { return nil })
	handler(cnf, w, r)
}

type JSONApi struct {
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
}

func getJWTBody(r *http.Request) (jwt.JWTBody, error) {
	authHeader := r.Header.Get("authorization")
	var encodedJWT string
	fmt.Sscanf(authHeader, "Bearer %s", &encodedJWT)

	decodedJWT, err := jwt.Decode(encodedJWT)
	if err != nil {
		return nil, fmt.Errorf("Unable to get body from jwt: %v", err)
	}
	jwtBody := decodedJWT.Body
	return jwtBody, nil
}

func handleGroupsGET(cnf *Config, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	encoder := json.NewEncoder(w)

	jwtBody, _ := getJWTBody(r)
	subId := jwtBody["sub"]

	params := mux.Vars(r)
	requestedId := params["user_id"]

	var user struct {
		Groups []string `json:"groups"`
	}
	cnf.Database.Collection("identities").FindOne(
		r.Context(),
		bson.D{{Key: "_id", Value: subId}},
	).Decode(&user)

	isSuperUser := false
	for _, g := range user.Groups {
		if g == "admin" || g == "manager" {
			isSuperUser = true
			break
		}
	}

	if subId != requestedId && !isSuperUser {
		w.WriteHeader(http.StatusForbidden)
		encoder.Encode(JSONApi{
			Message: "Not Authorized",
		})
		return
	}

	cnf.Database.Collection("identities").FindOne(
		r.Context(),
		bson.D{{Key: "_id", Value: requestedId}},
	).Decode(&user)

	if user.Groups == nil {
		user.Groups = []string{}
	}

	encoder.Encode(JSONApi{
		Data: user,
	})
}
