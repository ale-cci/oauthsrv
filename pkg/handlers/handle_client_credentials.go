// Client credentials
// Obtain authorization by providing client_id + client_password
package handlers

import (
	_ "go.mongodb.org/mongo-driver/bson"
	_ "go.mongodb.org/mongo-driver/mongo"
	"net/http"
)

type Client int

// Check database client credentials
func authorizeClientCredentials(cnf *Config, clientId, clientSecret string) (Client, error) {
	// cnf.Database.Collection("applications")

	return 0, nil
}

func handleClientCredentials(cnf *Config, w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// client_id := r.PostFormValue("client_id")
	client_secret := r.FormValue("client_secret")

	if client_secret == "client-secret" {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
	}
}
