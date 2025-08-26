// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package responder

// this implementation is intentionally kept with minimal dependencies
// as this package typically runs in its own process
import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// defaultTimeout used for shutdown
var defaultTimeout = 30 * time.Second

// Server wraps a minimal http server for the /hello endpoint
type Server struct {
	httpServers []*http.Server
}

// NewServer creates a new server listening on the given port
func NewServers(address []string, port int) *Server {
	if len(address) == 0 {
		address = []string{""}
	}

	server := &Server{}
	for _, ip := range address {
		addr := net.JoinHostPort(ip, fmt.Sprintf("%v", port))
		hs := http.Server{
			Addr:    addr,
			Handler: http.HandlerFunc(serverRequests),
		}
		server.httpServers = append(server.httpServers, &hs)
	}

	return server
}

// Serve http requests until shut down
func (s *Server) Serve() error {
	errors := make(chan error)
	for _, hs := range s.httpServers {
		tmpHttpServer := hs
		go func() {
			errors <- tmpHttpServer.ListenAndServe()
		}()
	}

	// Block for the first error, then return.
	err := <-errors
	return err
}

// Shutdown server gracefully
func (s *Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	errs := make([]error, 0, len(s.httpServers))
	for _, hs := range s.httpServers {
		errs = append(errs, hs.Shutdown(ctx))
	}

	return errors.Join(errs...)
}

func serverRequests(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/hello" {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
}
