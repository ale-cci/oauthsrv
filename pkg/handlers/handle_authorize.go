package handlers

import (
	"html/template"
	"net/http"
)

/**
 * Middleware for multiple grant types
 */
func handleAuth(cnf *Config, w http.ResponseWriter, r *http.Request) {
	// Detect grant type
	grant_type := r.URL.Query().Get("grant_type")
	// Switch based on grant type
	switch grant_type {
	case "code":
		Authorize(handleGrantCode)(cnf, w, r)
		break

	case "client_credentials":
		handleClientCredentials(cnf, w, r)
		break
	case "password":
		handleGrantPassword(cnf, w, r)
		break
	default:
		http.Error(w, "Grant type not found", http.StatusBadRequest)
	}
}

func handleGrantCode(cnf *Config, w http.ResponseWriter, r *http.Request) {
	type Error struct {
		Message string
	}

	q := r.URL.Query()
	errors := []Error{}

	if q.Get("client_id") == "" {
		errors = append(errors, Error{Message: "Missing client id"})
	}

	t, _ := template.ParseFiles("templates/authorize.tmpl")

	if len(errors) != 0 {
		w.WriteHeader(http.StatusBadRequest)
	}

	t.Execute(w, struct {
		Errors []Error
	}{
		Errors: errors,
	})
}
