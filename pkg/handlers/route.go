package handlers

import (
	"github.com/ale-cci/oauthsrv/pkg/jwt"
	"html/template"
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
				q := r.URL.Query()
				if q.Get("client_id") == "" {
					http.Error(w, "missing client id", http.StatusBadRequest)
				}
				t, _ := template.ParseFiles("templates/authorize.tmpl")
				t.Execute(w, nil)
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
