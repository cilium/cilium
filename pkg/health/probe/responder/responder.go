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
	"sync"
	"time"
)

// defaultTimeout used for shutdown
var defaultTimeout = 30 * time.Second

var listenRetryInterval = 5 * time.Second

// Server wraps a minimal http server for the /hello endpoint
type Server struct {
	// addresses is read when a listener binds rather than when the server is
	// created, so that a listener follows the node address.
	addresses func() []string
	port      int

	httpServers []*http.Server
	shutdown    chan struct{}
	shutdownOne sync.Once
}

// NewServer creates a new server listening on the given port
func NewServers(address []string, port int) *Server {
	return newServers(func() []string { return address }, port)
}

// NewServersFunc is NewServers for addresses that change while running:
// addresses is called again every time a listener binds.
func NewServersFunc(addresses func() []string, port int) *Server {
	return newServers(addresses, port)
}

func newServers(addresses func() []string, port int) *Server {
	s := &Server{addresses: addresses, port: port, shutdown: make(chan struct{})}
	for range addresses() {
		s.httpServers = append(s.httpServers, &http.Server{
			Handler: http.HandlerFunc(serverRequests),
		})
	}
	return s
}

func (s *Server) listenAddr(i int) string {
	ips := s.addresses()
	if i >= len(ips) {
		return ""
	}
	return net.JoinHostPort(ips[i], fmt.Sprintf("%v", s.port))
}

// Serve http requests until shut down, rebinding a listener whose address is
// not assignable yet or has since changed.
func (s *Server) Serve() error {
	var wg sync.WaitGroup
	for i, hs := range s.httpServers {
		wg.Go(func() {
			for {
				if hs.Addr = s.listenAddr(i); hs.Addr != "" {
					if errors.Is(hs.ListenAndServe(), http.ErrServerClosed) {
						return
					}
				}
				select {
				case <-s.shutdown:
					return
				case <-time.After(listenRetryInterval):
				}
			}
		})
	}
	wg.Wait()
	return http.ErrServerClosed
}

// Shutdown server gracefully
func (s *Server) Shutdown() error {
	s.shutdownOne.Do(func() { close(s.shutdown) })

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
