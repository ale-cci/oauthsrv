/**
 * Minimal router package, only intent is to add support for url parameters.
 */
package mux

import (
	"context"
	"net/http"
	"regexp"
)

const varsContextKey string = "vars"

type Router struct {
	handlers map[*regexp.Regexp]http.HandlerFunc
}

func NewServeMux() *Router {
	return &Router{
		handlers: map[*regexp.Regexp]http.HandlerFunc{},
	}
}

func Vars(r *http.Request) map[string]string {
	if params := r.Context().Value(varsContextKey); params != nil {
		return params.(map[string]string)
	}
	return map[string]string{}
}

func (router *Router) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	reg := regexp.MustCompile("^" + pattern + "$")
	router.handlers[reg] = handler
}

func matchURL(pattern *regexp.Regexp, url string) (map[string]string, bool) {
	if !pattern.MatchString(url) {
		return nil, false
	}

	matches := pattern.FindStringSubmatch(url)
	params := make(map[string]string)

	for i, name := range pattern.SubexpNames() {
		if i > 0 && i <= len(matches) {
			params[name] = matches[i]
		}
	}

	return params, true
}

func (router *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for reg, handler := range router.handlers {
		if params, ok := matchURL(reg, r.URL.EscapedPath()); ok {
			ctx := context.WithValue(r.Context(), varsContextKey, params)
			handler(w, r.WithContext(ctx))
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
}
