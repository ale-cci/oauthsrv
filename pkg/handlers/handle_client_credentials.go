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
	w.WriteHeader(http.StatusUnauthorized)
}
