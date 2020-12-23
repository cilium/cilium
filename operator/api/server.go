// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"context"
	"net"
	"net/http"
	"syscall"

	operatorApi "github.com/cilium/cilium/api/v1/operator/server"
	"github.com/cilium/cilium/api/v1/operator/server/restapi"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/go-openapi/loads"
	"golang.org/x/sys/unix"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "cilium-operator-api")

	noOpFunc = func() error {
		return nil
	}
)

// Server is the type corresponding to cilium-operator apiserver.
type Server struct {
	operatorApi.Server

	shutdownSignal <-chan struct{}
	allSystemsGo   <-chan struct{}

	checkStatus func() error

	listenAddrs []string
}

// newServer instantiates a new instance of the cilium-operator API server.
func (s *Server) newServer(spec *loads.Document) *operatorApi.Server {
	api := restapi.NewCiliumOperatorAPI(spec)
	api.Logger = log.Debugf

	// Register API handlers for the operator apiserver
	api.OperatorGetHealthzHandler = NewGetHealthzHandler(s)
	api.MetricsGetMetricsHandler = NewGetMetricsHandler(s)

	srv := operatorApi.NewServer(api)
	srv.EnabledListeners = []string{"http"}

	srv.ConfigureAPI()

	return srv
}

// NewServer creates a server to handle cilium-operator requests.
func NewServer(shutdownSignal <-chan struct{}, allSystemsGo <-chan struct{}, addrs ...string) (*Server, error) {
	server := &Server{
		listenAddrs: addrs,

		shutdownSignal: shutdownSignal,
		allSystemsGo:   allSystemsGo,

		checkStatus: noOpFunc,
	}

	swaggerSpec, err := loads.Analyzed(operatorApi.SwaggerJSON, "")
	if err != nil {
		return nil, err
	}

	server.Server = *server.newServer(swaggerSpec)
	return server, nil
}

// WithStatusCheckFunc returns the server configuring the check status function
// to return the health of the operator.
func (s *Server) WithStatusCheckFunc(f func() error) *Server {
	s.checkStatus = f
	return s
}

// Serve spins up the following goroutines:
// * TCP API Server: Responders to the health API "/hello" message, one per path
// * Prober: Periodically run pings across the cluster at a configured interval
//   and update the server's connectivity status cache.
// * Unix API Server: Handle all health API requests over a unix socket.
//
// Callers should first defer the Server.Shutdown(), then call Serve().
func (s *Server) Serve() error {
	errs := make(chan error, 1)
	nServers := 0

	// Since we are opening this on localhost only, we need to make sure
	// we can open for both v4 and v6 localhost. In case the user is running
	// v4-only or v6-only.
	for _, addr := range s.listenAddrs {
		if addr == "" {
			continue
		}
		nServers++
		srv := &http.Server{
			Addr:    addr,
			Handler: s.Server.GetHandler(),
		}
		errCh := make(chan error, 1)

		lc := net.ListenConfig{Control: setsockoptReuseAddrAndPort}
		ln, err := lc.Listen(context.Background(), "tcp", addr)
		if err != nil {
			log.WithError(err).Fatalf("Unable to listen on %s for healthz apiserver", addr)
		}

		go func() {
			err := srv.Serve(ln)
			if err != nil {
				errCh <- err
				errs <- err
			}
		}()

		go func() {
			select {
			case <-s.shutdownSignal:
				if err := srv.Shutdown(context.Background()); err != nil {
					log.WithError(err).Error("apiserver shutdown")
				}
			case err := <-errCh:
				log.WithError(err).Warn("Unable to start status api")
			}
		}()
		log.Infof("Starting apiserver on address %s", addr)
	}

	for err := range errs {
		nServers--
		if nServers == 0 {
			return err
		}
	}

	return nil
}

// setsockoptReuseAddrAndPort sets SO_REUSEADDR and SO_REUSEPORT
func setsockoptReuseAddrAndPort(network, address string, c syscall.RawConn) error {
	var soerr error
	if err := c.Control(func(su uintptr) {
		s := int(su)
		// Allow reuse of recently-used addresses. This socket option is
		// set by default on listeners in Go's net package, see
		// net setDefaultListenerSockopts
		soerr = unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		if soerr != nil {
			return
		}
		// Allow reuse of recently-used ports. This gives the operator a
		// better change to re-bind upon restarts.
		soerr = unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	}); err != nil {
		return err
	}
	return soerr
}
