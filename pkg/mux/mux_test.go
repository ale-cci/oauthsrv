package mux_test

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ale-cci/oauthsrv/pkg/mux"
	"gotest.tools/assert"
)

func TestMux(t *testing.T) {
	router := mux.NewServeMux()
	router.HandleFunc("/test/(?P<id>\\w+)", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)

		testId, ok := mux.Vars(r)["id"]
		var resp string
		if !ok {
			resp = fmt.Sprintf("hello")
		} else {
			resp = fmt.Sprintf("hello from %s", testId)
		}
		w.Write([]byte(resp))
	})
	srv := httptest.NewServer(router)
	defer srv.Close()

	t.Run("should return 200", func(t *testing.T) {
		resp, err := srv.Client().Get(srv.URL + "/test/1")
		assert.NilError(t, err)
		assert.Equal(t, resp.StatusCode, 200)

		body, err := ioutil.ReadAll(resp.Body)
		assert.NilError(t, err)
		assert.Equal(t, string(body), "hello from 1")
	})

	t.Run("should return 404 for unregistered urls", func(t *testing.T) {
		resp, err := srv.Client().Get(srv.URL + "/test")
		assert.NilError(t, err)
		assert.Equal(t, resp.StatusCode, http.StatusNotFound)
	})

	t.Run("should not match if pattern isn't at the start", func(t *testing.T) {
		resp, err := srv.Client().Get(srv.URL + "/another/test/1")
		assert.NilError(t, err)
		assert.Equal(t, resp.StatusCode, http.StatusNotFound)
	})

	t.Run("should not match if pattern isn't at the end", func(t *testing.T) {
		resp, err := srv.Client().Get(srv.URL + "/test/1/subsection")
		assert.NilError(t, err)
		assert.Equal(t, resp.StatusCode, http.StatusNotFound)
	})

	t.Run("should add value provided as url parameter", func(t *testing.T) {
		resp, err := srv.Client().Get(srv.URL + "/test/the_value")
		assert.NilError(t, err)
		assert.Equal(t, resp.StatusCode, http.StatusOK)

		body, err := ioutil.ReadAll(resp.Body)
		assert.NilError(t, err)
		assert.Equal(t, string(body), "hello from the_value")
	})
}
