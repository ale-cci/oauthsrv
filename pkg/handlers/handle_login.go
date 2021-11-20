package handlers

import (
	"github.com/ale-cci/oauthsrv/pkg/jwt"
	"github.com/ale-cci/oauthsrv/pkg/passwords"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"html/template"
	"log"
	"net/http"
)

func handleLogin(cnf *Config, w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		_, err := r.Cookie("sid")
		if err != http.ErrNoCookie {
			http.Redirect(w, r, "/continue", http.StatusFound)
			return
		}

		t, err := template.ParseFiles("templates/login.html")
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

		var identity struct {
			Email    string `bson:"_id"`
			Password string `bson:"password"`
		}
		err := cnf.Database.Collection("identities").FindOne(
			r.Context(),
			bson.D{{Key: "_id", Value: username}},
		).Decode(&identity)

		if err != nil {
			if err != mongo.ErrNoDocuments {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, r.URL.RequestURI(), http.StatusFound)
			return
		}

		if err := passwords.Validate(identity.Password, password); err != nil {
			log.Println(err.Error())
			http.SetCookie(w, &http.Cookie{Name: "error", Value: "Wrong username or password"})
			http.Redirect(w, r, r.URL.RequestURI(), http.StatusFound)
			return
		}

		sid := jwt.JWT{}.Encode(nil)

		http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid})
		http.Redirect(w, r, afterLogin, http.StatusFound)
	}
}
