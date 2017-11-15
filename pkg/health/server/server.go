// Copyright 2017 Authors of Cilium
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

package server

import (
	"time"

	healthApi "github.com/cilium/cilium/api/v1/health/server"
	"github.com/cilium/cilium/api/v1/health/server/restapi"
	"github.com/cilium/cilium/common"
	ciliumPkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/health/defaults"

	"github.com/go-openapi/loads"
	flags "github.com/jessevdk/go-flags"
)

var (
	log = common.DefaultLogger
)

// Config stores the configuration data for a cilium-health server.
type Config struct {
	Debug     bool
	CiliumURI string
}

// Server is the cilium-health daemon that is in charge of performing health
// and connectivity checks periodically, and serving the cilium-health API.
type Server struct {
	healthApi.Server  // Server to provide cilium-health API
	*ciliumPkg.Client // Client to "GET /healthz" on cilium daemon
	Config

	startTime time.Time
}

// DumpUptime returns the time that this server has been running.
func (s *Server) DumpUptime() string {
	return time.Since(s.startTime).String()
}

// NewServer creates a server to handle health requests.
func NewServer(config Config) (*Server, error) {
	server := &Server{
		startTime: time.Now(),
		Config:    config,
	}

	swaggerSpec, err := loads.Analyzed(healthApi.SwaggerJSON, "")
	if err != nil {
		return nil, err
	}

	if cl, err := ciliumPkg.NewClient(config.CiliumURI); err != nil {
		return nil, err
	} else {
		server.Client = cl
	}

	api := restapi.NewCiliumHealthAPI(swaggerSpec)
	api.Logger = log.Printf

	// /healthz/
	api.GetHealthzHandler = NewGetHealthzHandler(server)

	// /status/
	// /status/probe/
	// FIXME: Implement /status

	srv := healthApi.NewServer(api)
	srv.EnabledListeners = []string{"unix"}
	srv.SocketPath = flags.Filename(defaults.SockPath)
	// FIXME: Initialize httpServerL
	// FIXME: Listen on ports 4240+ for Connectivity probes
	srv.ConfigureAPI()
	server.Server = *srv

	return server, nil
}
