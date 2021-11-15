package handlers

import "net/http"

func handleGrantPassword(cnf *Config, w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Nope", http.StatusUnauthorized)
}
