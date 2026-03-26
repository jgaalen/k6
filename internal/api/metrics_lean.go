//go:build lean

package api

import (
	"net/http"
)

func metricsHandler() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Add("Content-Type", "text/plain; charset=utf-8")
		rw.WriteHeader(http.StatusNotFound)
		_, _ = rw.Write([]byte("Prometheus metrics endpoint is not available in this lean build"))
	})
}
