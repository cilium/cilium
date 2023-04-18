package cmd

import (
	"net/http"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"

	"github.com/go-openapi/loads"

	"github.com/cilium/cilium/api/v1/server"
	"github.com/cilium/cilium/api/v1/server/restapi"
	"github.com/cilium/cilium/pkg/hive/cell"
)

var apiServerCell = cell.Module(
	"cilium-api-server",
	"Serves the Cilium API",

	cell.Provide(newAPIServer),

	cell.Invoke(func(*APIServer) {}),
)

type APIServer struct {
	server http.Server

	mux            *http.ServeMux
	grpcServer     *grpc.Server
	swaggerHandler http.Handler
}

func (s *APIServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.ProtoMajor == 2 && strings.HasPrefix(
		req.Header.Get("Content-Type"), "application/grpc") {
		s.grpcServer.ServeHTTP(w, req)
	} else {
		s.swaggerHandler.ServeHTTP(w, req)
	}
}

func newAPIServer() (*APIServer, error) {
	s := &APIServer{
		mux:        http.NewServeMux(),
		grpcServer: grpc.NewServer(),
	}

	s.mux.Handle("/", s.grpcServer)

	spec, err := loads.Analyzed(server.SwaggerJSON, "")
	if err != nil {
		return nil, err
	}
	api := restapi.NewCiliumAPIAPI(spec)
	s.swaggerHandler = api.Serve(nil)

	s.server.Addr = ":8456"
	s.server.Handler = h2c.NewHandler(s, &http2.Server{})
	go s.server.ListenAndServe()
	return s, nil
}
