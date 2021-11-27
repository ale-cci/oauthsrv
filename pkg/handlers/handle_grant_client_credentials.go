// Client credentials
// Obtain authorization by providing client_id + client_password
package handlers

import (
	"encoding/json"
	"github.com/ale-cci/oauthsrv/pkg/jwt"
	"github.com/ale-cci/oauthsrv/pkg/passwords"
	"go.mongodb.org/mongo-driver/bson"
	"net/http"
)

func handleClientCredentials(cnf *Config, w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	client_id := r.FormValue("client_id")
	client_secret := r.FormValue("client_secret")

	var app struct {
		Id     string `bson:"_id"`
		Secret string `bson:"client_secret"`
	}

	err := cnf.Database.Collection("apps").FindOne(r.Context(), bson.D{
		{Key: "_id", Value: client_id},
	}).Decode(&app)

	if err != nil || passwords.Validate(app.Secret, client_secret) != nil {
		w.WriteHeader(http.StatusUnauthorized)
	} else {
		token := jwt.JWT{
			Head: &jwt.JWTHead{
				Typ: "JWT",
				Alg: "none",
			},
			Body: jwt.JWTBody{
				// uniquely identifies the user
				"sub": client_id,
			},
		}

		tokenB64, _ := token.Encode(nil)
		jsonBody, err := json.Marshal(struct {
			Jwt string `json:"jwt"`
		}{tokenB64})

		if err != nil {
			http.Error(w, "unable to build jwt", http.StatusInternalServerError)
		} else {
			w.Write(jsonBody)
		}
	}
}
