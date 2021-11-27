package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ale-cci/oauthsrv/pkg/jwt"
	"github.com/ale-cci/oauthsrv/pkg/passwords"
	"go.mongodb.org/mongo-driver/bson"
)

type Identity struct {
	Uid      string `bson:"_id"`
	Email    string `bson:"email"`
	Password string `bson:"password"`
}

func GetIdentity(context context.Context, cnf *Config, username, password string) (*Identity, error) {
	var identity Identity

	err := cnf.Database.Collection("identities").FindOne(
		context,
		bson.D{{Key: "email", Value: username}},
	).Decode(&identity)

	if err != nil {
		return nil, fmt.Errorf("Unable to fetch user: %v", err)
	}

	if err := passwords.Validate(identity.Password, password); err != nil {
		return nil, fmt.Errorf("Password validation failure: %v", err)
	}

	return &identity, nil
}

func handleGrantPassword(cnf *Config, w http.ResponseWriter, r *http.Request) {
	enc := json.NewEncoder(w)

	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		enc.Encode(map[string]string{
			"status":  "error",
			"message": "Method not allowed",
		})
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	identity, err := GetIdentity(r.Context(), cnf, username, password)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		enc.Encode(map[string]string{
			"status":  "error",
			"message": "Not Authorized",
		})
		return
	}

	tokenB64, err := jwt.NewJWT(cnf.Keystore, jwt.JWTBody{
		"sub": identity.Uid,
	})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		enc.Encode(map[string]string{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	enc.Encode(map[string]string{
		"access_token": tokenB64,
	})
}
