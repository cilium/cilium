// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"

	"github.com/go-openapi/loads"
	"github.com/go-openapi/runtime"
	"golang.org/x/sys/unix"

	operatorApi "github.com/cilium/cilium/api/v1/operator/server"
	"github.com/cilium/cilium/api/v1/operator/server/restapi"
	"github.com/cilium/cilium/api/v1/operator/server/restapi/operator"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
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

	// This is the /healthz handler outside of the open-api spec.
	healthzHandler *getHealthz

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

	server.healthzHandler = &getHealthz{Server: server}

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

// StartServer starts the HTTP listeners for the apiserver.
func (s *Server) StartServer() error {
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

		mux := http.NewServeMux()

		// Index handler is the the handler for Open-API router.
		mux.Handle("/", s.Server.GetHandler())
		// Create a custom handler for /healthz as an alias to /v1/healthz. A http mux
		// is required for this because open-api spec does not allow multiple base paths
		// to be specified.
		mux.HandleFunc("/healthz", func(rw http.ResponseWriter, _ *http.Request) {
			resp := s.healthzHandler.Handle(operator.GetHealthzParams{})
			resp.WriteResponse(rw, runtime.TextProducer())
		})

		srv := &http.Server{
			Addr:    addr,
			Handler: mux,
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
				// If the error is due to the server being shutdown, then send nil to
				// the server errors channel.
				if errors.Is(err, http.ErrServerClosed) {
					log.WithField("address", addr).Debug("Operator API server closed")
					errs <- nil
				} else {
					errCh <- err
					errs <- err
				}
			}
		}()

		go func() {
			select {
			case <-s.shutdownSignal:
				if err := srv.Shutdown(context.Background()); err != nil {
					log.WithError(err).Error("apiserver shutdown")
				}
			case err := <-errCh:
				log.WithError(err).Warn("Unable to start operator API server")
			}
		}()

		log.Infof("Starting apiserver on address %s", addr)
	}

	var retErr error
	for err := range errs {
		if err != nil {
			retErr = err
		}

		nServers--
		if nServers == 0 {
			return retErr
		}
	}

	return nil
}

// setsockoptReuseAddrAndPort sets the SO_REUSEADDR and SO_REUSEPORT socket options on c's
// underlying socket in order to improve the chance to re-bind to the same address and port
// upon restart.
func setsockoptReuseAddrAndPort(network, address string, c syscall.RawConn) error {
	var soerr error
	if err := c.Control(func(su uintptr) {
		s := int(su)
		// Allow reuse of recently-used addresses. This socket option is
		// set by default on listeners in Go's net package, see
		// net setDefaultListenerSockopts
		if err := unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			soerr = fmt.Errorf("failed to setsockopt(SO_REUSEADDR): %w", err)
			return
		}
		// Allow reuse of recently-used ports. This gives the agent a
		// better chance to re-bind upon restarts.
		if err := unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			soerr = fmt.Errorf("failed to Setsockopt(SO_REUSEPORT): %w", err)
		}
	}); err != nil {
		return err
	}
	return soerr
}
