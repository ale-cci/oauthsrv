package mux

import (
	"net/http"
	"regexp"
)

type Router struct {
	handlers map[*regexp.Regexp]http.HandlerFunc
}

func NewServeMux() *Router {
	return &Router{
		handlers: map[*regexp.Regexp]http.HandlerFunc{},
	}
}

func (router *Router) Vars(r *http.Request) map[string]string {
	return map[string]string{
		"id": "1",
	}
}

func (router *Router) HandleFunc(pattern string, handler http.HandlerFunc) {
	reg := regexp.MustCompile(pattern)
	router.handlers[reg] = handler
}

func (router *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	for reg, handler := range router.handlers {
		if reg.MatchString(r.URL.EscapedPath()) {
			handler(w, r)
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
}
