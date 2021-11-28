package handlers

import (
	"net/http"

	"github.com/ale-cci/oauthsrv/pkg/jwt"
)

func handleGroups(cnf *Config, w http.ResponseWriter, r *http.Request) {
	handler := CheckJWT(handleGroupsGET, func(_ jwt.JWTBody) error { return nil })
	handler(cnf, w, r)
}

func handleGroupsGET(cnf *Config, w http.ResponseWriter, r *http.Request) {
}
