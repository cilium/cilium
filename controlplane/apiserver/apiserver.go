// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package apiserver

import (
	"github.com/go-openapi/loads"

	"github.com/cilium/cilium/api/v1/server"
	"github.com/cilium/cilium/api/v1/server/restapi"
	. "github.com/cilium/cilium/api/v1/server/restapi/service"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// XXX take as dep
var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "apiserver")

var Cell = cell.Module(
	"api-server",
	"Cilium API Server",

	cell.Provide(newServer),
	cell.Invoke(func(*server.Server) {}),
)

type serverHandlers struct {
	cell.In

	PutServiceIDHandler    `optional:"true"`
	DeleteServiceIDHandler `optional:"true"`
	GetServiceIDHandler    `optional:"true"`
	GetServiceHandler      `optional:"true"`
	GetLrpHandler          `optional:"true"`
}

type serverParams struct {
	cell.In

	Lifecycle hive.Lifecycle
	Handlers  serverHandlers
}

func instantiateAPI(h serverHandlers) *restapi.CiliumAPIAPI {
	swaggerSpec, err := loads.Analyzed(server.SwaggerJSON, "")
	if err != nil {
		log.WithError(err).Fatal("Cannot load swagger spec")
	}

	restAPI := restapi.NewCiliumAPIAPI(swaggerSpec)
	restAPI.Logger = log.Infof
	restAPI.ServiceGetServiceIDHandler = h.GetServiceIDHandler
	restAPI.ServiceDeleteServiceIDHandler = h.DeleteServiceIDHandler
	restAPI.ServicePutServiceIDHandler = h.PutServiceIDHandler
	restAPI.ServiceGetServiceHandler = h.GetServiceHandler
	restAPI.ServiceGetLrpHandler = h.GetLrpHandler

	return restAPI
}

func newServer(p serverParams) (*server.Server, error) {
	srv := server.NewServer(instantiateAPI(p.Handlers))
	srv.EnabledListeners = []string{"unix"}
	srv.SocketPath = "/tmp/lbtest.sock"
	/*srv.ReadTimeout = apiTimeout
	srv.WriteTimeout = apiTimeout*/
	srv.ConfigureAPI()
	p.Lifecycle.Append(hive.Hook{
		OnStart: func(hive.HookContext) error {
			go srv.Serve()
			// TODO need to wait for Serve to return in
			// stop hook.
			return nil
		},
		OnStop: func(hive.HookContext) error {
			return srv.Shutdown()

		},
	})
	return srv, nil
}
