package handlers

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/ale-cci/oauthsrv/pkg/jwt"
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

/**
 * Middleware for server-side responses. If a user is calling an endpoint and
 * it's not authenticated, it is automatically redirected to the
 * login page.
 */
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

/**
 * Middleware that checks jwt validity before invoking an endpoint.
 * According to https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
 * the scopeChecker function is called after jwt validation.
 * in case the jwt doesn't have the required scopes it should return an error
 */
func CheckJWT(handler CnfHandlerFunc, scopeChecker func(jwt.JWTBody) error) CnfHandlerFunc {
	return func(cnf *Config, w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("authorization")
		var encodedJWT string
		_, err := fmt.Sscanf(auth, "Bearer %s", &encodedJWT)

		if err != nil {
			// JWT not provided
			w.Header().Set("www-authenticate", "Bearer error=\"invalid_request\"")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		decodedJWT, err := jwt.Decode(encodedJWT)
		if err != nil || decodedJWT.Verify(cnf.Keystore) != nil {
			// the provided jwt doesn't rispect the jwt format or it's
			// not verifiable.
			w.Header().Set("www-authenticate", "Bearer error=\"invalid_token\"")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if err := scopeChecker(decodedJWT.Body); err != nil {
			// Provided jwt does not have the requied scopes
			w.Header().Set("www-authenticate", "Bearer error=\"insufficient_scope\"")
			w.WriteHeader(http.StatusForbidden)
		} else {
			handler(cnf, w, r)
		}
	}
}
