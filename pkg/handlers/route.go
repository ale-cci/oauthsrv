package handlers

import (
	"github.com/ale-cci/oauthsrv/pkg/jwt"
	"net/http"
	"net/url"
)

type CnfHandlerFunc func(cnf *Config, w http.ResponseWriter, r *http.Request)

type Router interface {
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}

// Register all handlers to a given router
func AddRoutes(cnf *Config, router Router) {
	routes := []struct {
		Endpoint string
		Handler  CnfHandlerFunc
	}{
		{"/healthcheck", handleHealthCheck},
		{"/login", handleLogin},
		{"/oauth/v2/auth", handleAuth},
	}
	for _, route := range routes {
		router.HandleFunc(route.Endpoint, cnf.apply(route.Handler))
	}

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

// Authorization for server-side responses, if the request is invalid,
// redirect to login page
func Authorize(handler CnfHandlerFunc) CnfHandlerFunc {
	return func(cnf *Config, w http.ResponseWriter, r *http.Request) {
		sid, err := r.Cookie("sid")
		if err != nil && err != http.ErrNoCookie {
			// do something
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		isValid := (err != http.ErrNoCookie)
		if isValid {
			_, tokenErr := jwt.Decode(sid.Value)
			isValid = tokenErr == nil

		}

		if !isValid {
			continueTo := url.QueryEscape(r.RequestURI)
			http.Redirect(w, r, "/login?continue="+continueTo, http.StatusFound)
		} else {
			handler(cnf, w, r)
		}
	}
}
