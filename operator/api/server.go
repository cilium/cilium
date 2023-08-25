// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"

	"github.com/go-openapi/loads"
	"github.com/go-openapi/runtime"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	operatorApi "github.com/cilium/cilium/api/v1/operator/server"
	"github.com/cilium/cilium/api/v1/operator/server/restapi"
	"github.com/cilium/cilium/api/v1/operator/server/restapi/metrics"
	"github.com/cilium/cilium/api/v1/operator/server/restapi/operator"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
)

type Server interface {
	// Ports returns the ports at which the server is listening
	Ports() []int
}

// params contains all the dependencies for the api server.
// They will be provided through dependency injection.
type params struct {
	cell.In

	Cfg Config

	HealthHandler   operator.GetHealthzHandler
	MetricsHandler  metrics.GetMetricsHandler
	OperatorAPISpec *operatorApi.Spec

	Logger     logrus.FieldLogger
	Lifecycle  hive.Lifecycle
	Shutdowner hive.Shutdowner
}

type server struct {
	*operatorApi.Server

	logger     logrus.FieldLogger
	shutdowner hive.Shutdowner

	address  string
	httpSrvs []httpServer

	healthHandler  operator.GetHealthzHandler
	metricsHandler metrics.GetMetricsHandler
	apiSpec        *operatorApi.Spec
}

type httpServer struct {
	address  string
	listener net.Listener
	server   *http.Server
}

func newServer(
	p params,
) (Server, error) {
	server := &server{
		logger:         p.Logger,
		shutdowner:     p.Shutdowner,
		address:        p.Cfg.OperatorAPIServeAddr,
		healthHandler:  p.HealthHandler,
		metricsHandler: p.MetricsHandler,
		apiSpec:        p.OperatorAPISpec,
	}
	p.Lifecycle.Append(server)

	return server, nil
}

func (s *server) Start(ctx hive.HookContext) error {
	spec, err := loads.Analyzed(operatorApi.SwaggerJSON, "")
	if err != nil {
		return err
	}

	restAPI := restapi.NewCiliumOperatorAPI(spec)
	restAPI.Logger = s.logger.Debugf
	restAPI.OperatorGetHealthzHandler = s.healthHandler
	restAPI.MetricsGetMetricsHandler = s.metricsHandler

	api.DisableAPIs(s.apiSpec.DeniedAPIs, restAPI.AddMiddlewareFor)
	srv := operatorApi.NewServer(restAPI)
	srv.EnabledListeners = []string{"http"}
	srv.ConfigureAPI()
	s.Server = srv

	mux := http.NewServeMux()

	// Index handler is the the handler for Open-API router.
	mux.Handle("/", s.Server.GetHandler())
	// Create a custom handler for /healthz as an alias to /v1/healthz. A http mux
	// is required for this because open-api spec does not allow multiple base paths
	// to be specified.
	mux.HandleFunc("/healthz", func(rw http.ResponseWriter, _ *http.Request) {
		resp := s.healthHandler.Handle(operator.GetHealthzParams{})
		resp.WriteResponse(rw, runtime.TextProducer())
	})

	if s.address == "" {
		// Since we are opening this on localhost only, we need to make sure
		// we can open for both v4 and v6 localhost, in case the user is running
		// v4-only or v6-only.
		s.httpSrvs = make([]httpServer, 2)
		s.httpSrvs[0].address = "127.0.0.1:0"
		s.httpSrvs[1].address = "[::1]:0"
	} else {
		s.httpSrvs = make([]httpServer, 1)
		s.httpSrvs[0].address = s.address
	}

	var errs []error
	for i := range s.httpSrvs {
		lc := net.ListenConfig{Control: setsockoptReuseAddrAndPort}
		ln, err := lc.Listen(ctx, "tcp", s.httpSrvs[i].address)
		if err != nil {
			errs = append(errs, fmt.Errorf("unable to listen on %s: %w", s.httpSrvs[i].address, err))
			continue
		}
		s.httpSrvs[i].listener = ln

		s.logger.WithFields(logrus.Fields{
			fmt.Sprintf("address-%d", i): ln.Addr().String(),
		})

		s.httpSrvs[i].server = &http.Server{
			Addr:    s.httpSrvs[i].address,
			Handler: mux,
		}
	}

	// if no apiserver can be started, we stop the cell
	if (len(s.httpSrvs) == 1 && s.httpSrvs[0].server == nil) ||
		(len(s.httpSrvs) == 2 && s.httpSrvs[0].server == nil && s.httpSrvs[1].server == nil) {
		s.shutdowner.Shutdown()
		return errors.Join(errs...)
	}

	// otherwise just log any possible error and continue
	for _, err := range errs {
		s.logger.WithError(err).Error("apiserver start failed")
	}

	for _, srv := range s.httpSrvs {
		if srv.server == nil {
			continue
		}
		go func(srv httpServer) {
			if err := srv.server.Serve(srv.listener); !errors.Is(err, http.ErrServerClosed) {
				s.logger.WithError(err).Error("server stopped unexpectedly")
				s.shutdowner.Shutdown()
			}
		}(srv)
	}

	return nil
}

// setsockoptReuseAddrAndPort sets the SO_REUSEADDR and SO_REUSEPORT socket options on c's
// underlying socket in order to improve the chance to re-bind to the same address and port
// upon restart.
func (s *server) Stop(ctx hive.HookContext) error {
	for _, srv := range s.httpSrvs {
		if srv.server == nil {
			continue
		}
		if err := srv.server.Shutdown(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (s *server) Ports() []int {
	ports := make([]int, 0, len(s.httpSrvs))
	for _, srv := range s.httpSrvs {
		if srv.server == nil {
			continue
		}
		ports = append(ports, srv.listener.Addr().(*net.TCPAddr).Port)
	}
	return ports
}

// setsockoptReuseAddrAndPort sets SO_REUSEADDR and SO_REUSEPORT
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

		// Allow reuse of recently-used ports. This gives the operator a
		// better chance to re-bind upon restarts.
		soerr = unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	}); err != nil {
		return err
	}
	return soerr
}
