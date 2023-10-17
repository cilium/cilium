package restapi

import (
	"net"
	"net/http"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/api/v1/server"
	"github.com/cilium/cilium/api/v1/server/restapi"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
)

var serverCell = cell.Module(
	"cilium-api-server",
	"Serves the Cilium API",

	cell.Config(APIServerConfig{}),
	cell.Provide(newAPIServer),

	hive.AppendHooks[*APIServer](),
)

type APIServer struct {
	api            *restapi.CiliumAPIAPI
	server         http.Server
	config         APIServerConfig
	mux            *http.ServeMux
	grpcServer     *grpc.Server
	swaggerHandler http.Handler
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
	} else {
		s.swaggerHandler.ServeHTTP(w, req)
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

	s.swaggerHandler = s.api.Serve(nil)
	s.server.Handler = h2c.NewHandler(s, &http2.Server{})

	go s.server.Serve(listener)
	return nil
}

func (s *APIServer) Stop(hive.HookContext) error {
	return s.server.Close()
}

func (s *APIServer) GetAPI() *restapi.CiliumAPIAPI {
	return s.api
}

type apiServerParams struct {
	cell.In

	Config   APIServerConfig
	Spec     *server.Spec
	Services []api.GRPCService `group:"grpc-services"`
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

	s.mux.Handle("/", s.grpcServer)

	s.api = restapi.NewCiliumAPIAPI(p.Spec.Document)

	// FIXME populate the API from handlers.

	return s, nil
}
