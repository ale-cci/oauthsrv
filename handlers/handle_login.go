package handlers

import (
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"net/http"
	"github.com/ale-cci/oauthsrv/passwords"
)

func handleLogin(cnf *Config, w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		_, err := r.Cookie("sid")
		if err != http.ErrNoCookie {
			http.Redirect(w, r, "/continue", http.StatusFound)
			return
		}
		w.WriteHeader(200)
	} else {
		username := r.FormValue("username")
		password := r.FormValue("password")
		afterLogin := r.URL.Query().Get("continue")

		var identity struct {
			Email    string `bson:"_id"`
			Password string `bson:"password"`
		}
		err := cnf.Database.Collection("identities").FindOne(r.Context(), bson.D{{Key: "_id", Value: username}}).Decode(&identity)

		if err != nil {
			if err != mongo.ErrNoDocuments {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, r.URL.RequestURI(), http.StatusFound)
			return
		}

		if err := passwords.Validate(identity.Password, password); err != nil {
			http.Redirect(w, r, r.URL.RequestURI(), http.StatusFound)
			return
		}

		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "1"})

		http.Redirect(w, r, afterLogin, http.StatusFound)
	}
}
