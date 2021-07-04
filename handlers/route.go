package handlers

import (
	"net/http"
)

type Router interface {
	HandleFunc(pattern string, handler func(w http.ResponseWriter, r *http.Request))
}

// Register all handlers to a given router
func AddRoutes(cnf *Config, router Router) {
	router.HandleFunc("/healthcheck", cnf.apply(handleHealthCheck))
}

// Healthcheck endpoint, returns 500 in case of problems
func handleHealthCheck(cnf *Config, w http.ResponseWriter, r *http.Request) {
	err := cnf.Database.Client().Ping(r.Context(), nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Ok!"))
}
