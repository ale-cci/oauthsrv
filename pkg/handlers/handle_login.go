package handlers

import (
	"html/template"
	"net/http"

	"github.com/ale-cci/oauthsrv/pkg/jwt"
	"github.com/ale-cci/oauthsrv/pkg/passwords"
)

func handleLogin(cnf *Config, w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		_, err := r.Cookie("sid")
		if err != http.ErrNoCookie {
			http.Redirect(w, r, "/continue", http.StatusFound)
			return
		}

		t, err := template.ParseFiles("templates/login.tmpl")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data := struct{ Error string }{}

		errmsg, err := r.Cookie("error")
		if err != http.ErrNoCookie {
			data.Error = errmsg.Value
		}

		if err := t.Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		username := r.FormValue("username")
		password := r.FormValue("password")
		afterLogin := r.URL.Query().Get("continue")

		identity, err := GetIdentity(r.Context(), cnf, username, password)

		if err != nil || passwords.Validate(identity.Password, password) != nil {
			http.SetCookie(w, &http.Cookie{Name: "error", Value: "Wrong username or password"})
			http.Redirect(w, r, r.URL.RequestURI(), http.StatusFound)
			return
		}

		sid, _ := jwt.NewJWT(cnf.Keystore, jwt.JWTBody{
			"sub": identity.Uid,
		})

		http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid})
		http.Redirect(w, r, afterLogin, http.StatusFound)
	}
}
