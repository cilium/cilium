// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/api/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
)

// Cell implements a gRPC server that is served over a UNIX socket
// defined by --socket-path. The served services are collect via
// [types.GRPCService] in group "grpc-services". Use [types.NewGRPCServiceOut]
// in your provide function to register the services.
//
// See [server_test.go] for an example.
var Cell = cell.Module(
	"api-server",
	"Modular gRPC server served over a UNIX socket",

	cell.Config(Config{
		SocketPath: defaults.SockPath,
	}),
	cell.Provide(newServer),
	cell.AppendHooks[*Server](),
)

type serverParams struct {
	cell.In

	Shutdowner hive.Shutdowner
	Log        logrus.FieldLogger
	Config     Config
	Services   []types.GRPCService `group:"grpc-services"`
}

type Server struct {
	log             logrus.FieldLogger
	shutdowner      hive.Shutdowner
	server          http.Server
	config          Config
	mux             *http.ServeMux
	grpcServer      *grpc.Server
	fallbackHandler http.Handler
}

type Config struct {
	SocketPath string
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.String("socket-path", def.SocketPath, "Sets the UNIX socket path for API connections")
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.ProtoMajor == 2 && strings.HasPrefix(
		req.Header.Get("Content-Type"), "application/grpc") {
		s.grpcServer.ServeHTTP(w, req)
	} else if s.fallbackHandler != nil {
		s.fallbackHandler.ServeHTTP(w, req)
	}
}

func (s *Server) Start(hive.HookContext) error {
	socketDir := path.Dir(s.config.SocketPath)
	if err := os.MkdirAll(socketDir, defaults.RuntimePathRights); err != nil {
		s.log.WithError(err).Fatal("Cannot mkdir directory for cilium socket")
	}
	if err := os.Remove(s.config.SocketPath); !os.IsNotExist(err) && err != nil {
		s.log.WithError(err).Fatal("Cannot remove existing Cilium sock")
	}

	addr, err := net.ResolveUnixAddr("unix", s.config.SocketPath)
	if err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return err
	}

	s.log.Infof("Serving API at unix://%s", s.config.SocketPath)

	go func() {
		err := s.server.Serve(listener)
		if !errors.Is(err, http.ErrServerClosed) {
			// Unexpected error while serving. Shut down the whole
			// application.
			err = fmt.Errorf("api-server failure in Serve(): %w", err)
			s.shutdowner.Shutdown(hive.ShutdownWithError(err))
		}
	}()
	return nil
}

func (s *Server) Stop(hive.HookContext) error {
	return s.server.Close()
}

func (s *Server) SetFallbackHandler(h http.Handler) {
	s.fallbackHandler = h
}

func newServer(p serverParams) (*Server, error) {
	s := &Server{
		shutdowner: p.Shutdowner,
		config:     p.Config,
		log:        p.Log,
		mux:        http.NewServeMux(),
		grpcServer: grpc.NewServer(),
	}

	for _, svc := range p.Services {
		s.grpcServer.RegisterService(svc.Service, svc.Impl)
	}

	// Use the h2c handler to allow for unencrypted HTTP/2
	s.server.Handler = h2c.NewHandler(s, &http2.Server{})
	s.mux.Handle("/", s.grpcServer)

	return s, nil
}
