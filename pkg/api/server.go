package api

import (
	"net"
	"net/http"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/api/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
)

var ServerCell = cell.Module(
	"api-server",
	"API Server",

	cell.Config(APIServerConfig{
		SocketPath: defaults.SockPath,
	}),
	cell.Provide(newAPIServer),

	hive.AppendHooks[*APIServer](),
)

type APIServer struct {
	server          http.Server
	config          APIServerConfig
	mux             *http.ServeMux
	grpcServer      *grpc.Server
	fallbackHandler http.Handler
}

type APIServerConfig struct {
	SocketPath string
}

func (def APIServerConfig) Flags(flags *pflag.FlagSet) {
	flags.String("socket-path", def.SocketPath, "Sets the UNIX socket path for API connections")
}

func (s *APIServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.ProtoMajor == 2 && strings.HasPrefix(
		req.Header.Get("Content-Type"), "application/grpc") {
		s.grpcServer.ServeHTTP(w, req)
	} else if s.fallbackHandler != nil {
		s.fallbackHandler.ServeHTTP(w, req)
	}
}

func (s *APIServer) Start(hive.HookContext) error {
	addr, err := net.ResolveUnixAddr("unix", s.config.SocketPath)
	if err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return err
	}

	go s.server.Serve(listener)
	return nil
}

func (s *APIServer) Stop(hive.HookContext) error {
	return s.server.Close()
}

func (s *APIServer) SetFallbackHandler(h http.Handler) {
	s.fallbackHandler = h
}

type apiServerParams struct {
	cell.In

	Config   APIServerConfig
	Services []types.GRPCService `group:"grpc-services"`
}

func newAPIServer(p apiServerParams) (*APIServer, error) {
	s := &APIServer{
		config:     p.Config,
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
