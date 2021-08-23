// Client credentials
// Obtain authorization by providing client_id + client_password
package handlers

import (
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
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{\"jwt\": \"test\"}"))
	}
}
