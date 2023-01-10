// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package responder

// this implementation is intentionally kept with minimal dependencies
// as this package typically runs in its own process
import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// defaultTimeout used for shutdown
var defaultTimeout = 30 * time.Second

// Server wraps a minimal http server for the /hello endpoint
type Server struct {
	httpServer http.Server
}

// NewServer creates a new server listening on the given port
func NewServer(port int) *Server {
	return &Server{
		http.Server{
			Addr:    fmt.Sprintf(":%d", port),
			Handler: http.HandlerFunc(serverRequests),
		},
	}
}

// Serve http requests until shut down
func (s *Server) Serve() error {
	return s.httpServer.ListenAndServe()
}

// Shutdown server gracefully
func (s *Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	return s.httpServer.Shutdown(ctx)
}

func serverRequests(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/hello" {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
}
