package handlers

import (
	"encoding/json"
	"github.com/ale-cci/oauthsrv/pkg/passwords"
	"go.mongodb.org/mongo-driver/bson"
	"log"
	"net/http"
)

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

	var identity struct {
		Email    string `bson:"_id"`
		Password string `bson:"password"`
	}

	err := cnf.Database.Collection("identities").FindOne(
		r.Context(),
		bson.D{{"_id", username}},
	).Decode(&identity)

	if err == nil {
		err = passwords.Validate(
			identity.Password,
			password,
		)
		log.Printf("Password checked %s, %s", identity.Password, password)
	}

	if err == nil {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
	}
	enc.Encode(map[string]string{
		"status":  "error",
		"message": "Not Authorized",
	})
}
