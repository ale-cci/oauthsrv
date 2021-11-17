package handlers

import (
	"encoding/json"
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
	// password := r.FormValue("password")

	if username == "test@email.com" {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
	}
	enc.Encode(map[string]string{
		"status":  "error",
		"message": "Not Authorized",
	})
}
