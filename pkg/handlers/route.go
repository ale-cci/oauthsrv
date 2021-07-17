package handlers

import (
	"net/http"
	"net/url"
)

type CnfHandlerFunc func(cnf *Config, w http.ResponseWriter, r *http.Request)

type Router interface {
	HandleFunc(pattern string, handler func(w http.ResponseWriter, r *http.Request))
}

// Register all handlers to a given router
func AddRoutes(cnf *Config, router Router) {
	router.HandleFunc("/healthcheck", cnf.apply(handleHealthCheck))
	router.HandleFunc("/login", cnf.apply(handleLogin))

	router.HandleFunc("/oauth/v2/auth", cnf.apply(
		Authorize(
			func(cnf *Config, w http.ResponseWriter, r *http.Request) {
			}),
	),
	)

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

func Authorize(handler CnfHandlerFunc) CnfHandlerFunc {
	return func(cnf *Config, w http.ResponseWriter, r *http.Request) {
		continueTo := url.QueryEscape(r.RequestURI)
		w.Header().Add("Location", "/login?continue="+continueTo)
		w.WriteHeader(http.StatusFound)
	}
}
