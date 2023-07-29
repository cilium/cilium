// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package responder

// this implementation is intentionally kept with minimal dependencies
// as this package typically runs in its own process
import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"time"
)

// defaultTimeout used for shutdown
var defaultTimeout = 30 * time.Second

// Server wraps a minimal http server for the /hello endpoint
type Server struct {
	httpServer []*http.Server
}

// NewServer creates a new server listening on the given port
func NewServer(address []string, port int) *Server {
	if address == nil {
		address = []string{""}
	}

	server := &Server{}
	for _, ip := range address {
		if ip != "" {
			ipBytes, _ := netip.ParseAddr(ip)
			if ipBytes.Is6() {
				// if ipv6 address, then listen address should be in format of [ipv6]:port
				ip = "[" + ip + "]"
			}
		}

		hs := http.Server{
			Addr:    fmt.Sprintf("%s:%d", ip, port),
			Handler: http.HandlerFunc(serverRequests),
		}
		server.httpServer = append(server.httpServer, &hs)
	}

	return server
}

// Serve http requests until shut down
func (s *Server) Serve() error {
	errors := make(chan error)
	for _, hs := range s.httpServer {
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
	var err error
	for _, hs := range s.httpServer {
		if tmpError := hs.Shutdown(ctx); tmpError != nil {
			err = tmpError
		}
	}

	return err
}

func serverRequests(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/hello" {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
}
