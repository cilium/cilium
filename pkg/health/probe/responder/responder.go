// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package responder

// this implementation is intentionally kept with minimal dependencies
// as this package typically runs in its own process
import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// defaultTimeout used for shutdown
var defaultTimeout = 30 * time.Second

// Server wraps a minimal http server for the /hello endpoint
type Server struct {
	mu          sync.Mutex
	port        int
	httpServers []*http.Server
	errCh       chan error
	closed      bool
}

// NewServer creates a new server listening on the given port
func NewServers(address []string, port int) *Server {
	server := &Server{
		port:  port,
		errCh: make(chan error, 1),
	}
	server.httpServers = newHTTPServers(address, port)
	return server
}

func newHTTPServers(addresses []string, port int) []*http.Server {
	if len(addresses) == 0 {
		addresses = []string{""}
	}

	servers := make([]*http.Server, 0, len(addresses))
	for _, ip := range addresses {
		addr := net.JoinHostPort(ip, strconv.Itoa(port))
		servers = append(servers, &http.Server{
			Addr:    addr,
			Handler: http.HandlerFunc(serverRequests),
		})
	}
	return servers
}

// Serve http requests until shut down
func (s *Server) Serve() error {
	s.serveHTTPServers()

	// Block for the first real error, then return.
	err := <-s.errCh
	return err
}

func (s *Server) serveHTTPServers() {
	s.mu.Lock()
	servers := s.httpServers
	s.mu.Unlock()

	for _, hs := range servers {
		go func(srv *http.Server) {
			// Bind errors are intentionally not propagated: a transient error
			// during Rebind (e.g. TIME_WAIT) must not cause Serve() to return.
			srv.ListenAndServe()
		}(hs)
	}
}

// swapServers atomically replaces the server list and reports whether the
// server is already closed. Returns (nil, true) if already shut down.
func (s *Server) swapServers(addresses []string) (old []*http.Server, closed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, true
	}
	old = s.httpServers
	s.httpServers = newHTTPServers(addresses, s.port)
	return old, false
}

// Rebind shuts down the current HTTP servers and starts new ones on the
// given addresses. Serve() continues to block transparently.
func (s *Server) Rebind(addresses []string) {
	old, closed := s.swapServers(addresses)
	if closed {
		return
	}
	shutdownServers(old)
	// Re-check closed: Shutdown() may have raced while we were draining.
	s.mu.Lock()
	closed = s.closed
	s.mu.Unlock()
	if closed {
		return
	}
	s.serveHTTPServers()
}

// Shutdown server gracefully
func (s *Server) Shutdown() error {
	s.mu.Lock()
	servers := s.httpServers
	alreadyClosed := s.closed
	s.closed = true
	s.mu.Unlock()

	errs := shutdownServers(servers)

	if !alreadyClosed {
		s.errCh <- http.ErrServerClosed
	}

	return errors.Join(errs...)
}

func shutdownServers(servers []*http.Server) []error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	errs := make([]error, 0, len(servers))
	for _, hs := range servers {
		errs = append(errs, hs.Shutdown(ctx))
	}
	return errs
}

func serverRequests(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/hello" {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
}
