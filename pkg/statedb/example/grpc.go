package main

import (
	"net/http"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/api/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
)

var apiServerCell = cell.Module(
	"api-server",
	"Serves the API",

	cell.Provide(newAPIServer),

	hive.AppendHooks[*APIServer](),
)

type APIServer struct {
	server http.Server

	mux        *http.ServeMux
	grpcServer *grpc.Server
}

func (s *APIServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.ProtoMajor == 2 && strings.HasPrefix(
		req.Header.Get("Content-Type"), "application/grpc") {
		s.grpcServer.ServeHTTP(w, req)
	}
}

func (s *APIServer) Start(hive.HookContext) error {
	go s.server.ListenAndServe()
	return nil
}

func (s *APIServer) Stop(ctx hive.HookContext) error {
	return s.server.Shutdown(ctx)
}

type apiServerParams struct {
	cell.In

	Log      logrus.FieldLogger
	Services []types.GRPCService `group:"grpc-services"`
}

func newAPIServer(p apiServerParams) (*APIServer, error) {
	s := &APIServer{
		mux:        http.NewServeMux(),
		grpcServer: grpc.NewServer(),
	}

	for _, svc := range p.Services {
		p.Log.Infof("Registering service %q", svc.Service.ServiceName)
		s.grpcServer.RegisterService(svc.Service, svc.Impl)
	}

	s.mux.Handle("/", s.grpcServer)

	s.server.Addr = ":8456"
	s.server.Handler = h2c.NewHandler(s, &http2.Server{})

	return s, nil
}
