// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package pprof

import (
	"errors"
	"net"
	"net/http"
	"net/http/pprof"
	_ "net/http/pprof"
	"strconv"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
)

const (
	// Pprof is the flag to enable the registration of pprof HTTP handlers
	Pprof = "pprof"

	// PprofAddress is the flag to set the address that pprof listens on
	PprofAddress = "pprof-address"

	// PprofPort is the flag to set the port that pprof listens on
	PprofPort = "pprof-port"
)

type Server interface {
	// Port returns the port at which the server is listening
	Port() int
}

// Cell creates the cell for pprof, that registers its HTTP handlers to serve
// profiling data in the format expected by the pprof visualization tool.
var Cell = cell.Module(
	"pprof",
	"pprof HTTP server to expose runtime profiling data",

	// We don't call cell.Config directly here, because the operator
	// uses different flags names for the same pprof config flags.
	// Therefore, to register each flag with the correct name, we leave
	// the call to cell.Config to the user of the cell.

	// Provide coupled with Invoke is used to improve cell testability,
	// namely to allow taking a reference to the Server and call Port() on it.
	cell.Provide(newServer),
	cell.Invoke(func(srv Server) {}),
)

// Config contains the configuration for the pprof cell.
type Config struct {
	Pprof        bool
	PprofAddress string
	PprofPort    uint16
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(Pprof, def.Pprof, "Enable serving pprof debugging API")
	flags.String(PprofAddress, def.PprofAddress, "Address that pprof listens on")
	flags.Uint16(PprofPort, def.PprofPort, "Port that pprof listens on")
}

func newServer(lc hive.Lifecycle, log logrus.FieldLogger, cfg Config) Server {
	if !cfg.Pprof {
		return nil
	}

	srv := &server{
		logger:  log,
		address: cfg.PprofAddress,
		port:    cfg.PprofPort,
	}
	lc.Append(srv)

	return srv
}

type server struct {
	logger logrus.FieldLogger

	address string
	port    uint16

	httpSrv  *http.Server
	listener net.Listener
}

func (s *server) Start(ctx hive.HookContext) error {
	listener, err := net.Listen("tcp", net.JoinHostPort(s.address, strconv.FormatUint(uint64(s.port), 10)))
	if err != nil {
		return err
	}
	s.listener = listener

	s.logger = s.logger.WithFields(logrus.Fields{
		"ip":   s.listener.Addr().(*net.TCPAddr).IP,
		"port": s.listener.Addr().(*net.TCPAddr).Port,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	s.httpSrv = &http.Server{
		Handler: mux,
	}
	go func() {
		if err := s.httpSrv.Serve(s.listener); !errors.Is(err, http.ErrServerClosed) {
			s.logger.WithError(err).Error("server stopped unexpectedly")
		}
	}()
	s.logger.Info("Started pprof server")

	return nil
}

func (s *server) Stop(ctx hive.HookContext) error {
	s.logger.Info("Stopped pprof server")
	return s.httpSrv.Shutdown(ctx)
}

func (s *server) Port() int {
	return s.listener.Addr().(*net.TCPAddr).Port
}
