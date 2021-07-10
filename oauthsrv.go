package main

import (
	"log"
	"net/http"

	"github.com/ale-cci/oauthsrv/pkg/handlers"
)

func main() {
	addr := ":8080"

	cnf, err := handlers.EnvConfig()
	if err != nil {
		log.Panicf("Unable to initialize server: %v", err)
	}

	router := http.NewServeMux()
	handlers.AddRoutes(cnf, router)

	log.Printf("Server started on %s", addr)
	http.ListenAndServe(addr, router)
}
