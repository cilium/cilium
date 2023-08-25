// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"errors"
	"net/http"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
)

var serverCell = cell.Module(
	"http-server",
	"Simple HTTP Server",

	cell.Config(defaultServerConfig),
	cell.Provide(newServer),
)

//
// Server API
//

type Server interface {
	// ListenAddress returns the address at which the server is listening,
	// e.g. ":8888".
	ListenAddress() string
}

// HTTPHandler specifies an HTTP handler for a specific path.
type HTTPHandler struct {
	Path    string           // Path to serve at, e.g. /hello
	Handler http.HandlerFunc // The handler to call for this path
}

// HTTPHandlerOut is a convenience struct for cells that implement
// only a single handler.
type HTTPHandlerOut struct {
	cell.Out

	HTTPHandler HTTPHandler `group:"http-handlers"`
}

//
// Server configuration
//

type serverConfig struct {
	ServerAddress string // Server listen address
}

func (def serverConfig) Flags(flags *pflag.FlagSet) {
	flags.String("server-address", def.ServerAddress, "HTTP server listen address")
}

// defaultServerConfig is the default server configuration.
var defaultServerConfig = serverConfig{
	ServerAddress: ":8888",
}

//
// Implementation
//

type serverParams struct {
	cell.In

	Config     serverConfig
	Log        logrus.FieldLogger
	Lifecycle  hive.Lifecycle
	Shutdowner hive.Shutdowner
	Handlers   []HTTPHandler `group:"http-handlers"`
}

type simpleServer struct {
	params serverParams
	server http.Server
}

func (s *simpleServer) listenAndServe() {
	s.params.Log.
		WithField("server-address", s.params.Config.ServerAddress).
		Info("Listening")

	err := s.server.ListenAndServe()
	if !errors.Is(err, http.ErrServerClosed) {
		// An unexpected error happened (e.g. failed to listen),
		// shut down the application.
		s.params.Shutdowner.Shutdown(hive.ShutdownWithError(err))
	}
}

func (s *simpleServer) ListenAddress() string {
	return s.server.Addr
}

func (s *simpleServer) Start(ctx hive.HookContext) error {
	go s.listenAndServe()
	return nil
}

func (s *simpleServer) Stop(ctx hive.HookContext) error {
	// Stop the server. Waits for clients to finish.
	return s.server.Shutdown(ctx)
}

func newServer(params serverParams) Server {
	mux := http.NewServeMux()
	s := &simpleServer{params: params}
	s.server.Addr = params.Config.ServerAddress
	s.server.Handler = mux
	for _, h := range params.Handlers {
		mux.HandleFunc(h.Path, h.Handler)
	}
	params.Lifecycle.Append(s)
	return s
}
