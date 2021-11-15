package handlers

import "net/http"

func handleGrantPassword(cnf *Config, w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
	http.Error(w, "Nope", http.StatusUnauthorized)
}
