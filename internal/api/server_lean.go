//go:build lean

// Package api is stubbed out in lean builds: the REST API server is not
// available and GetServer returns a server that responds to all requests with
// an explanatory message.
package api

import (
	"context"
	"net/http"
	"time"

	"go.k6.io/k6/v2/internal/execution"
	"go.k6.io/k6/v2/internal/metrics/engine"
	"go.k6.io/k6/v2/lib"
	"go.k6.io/k6/v2/metrics"
)

// GetServer returns a stub *http.Server in the lean build. The server will
// listen on the given address but only responds with a notice that the REST
// API is unavailable.
func GetServer(
	_ context.Context,
	addr string,
	_ bool,
	_ *lib.TestRunState,
	_ chan metrics.SampleContainer,
	_ *engine.MetricsEngine,
	_ *execution.Scheduler,
) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
		rw.WriteHeader(http.StatusServiceUnavailable)
		_, _ = rw.Write([]byte("The REST API is not available in this lean build of k6.\n"))
	})
	return &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
}
