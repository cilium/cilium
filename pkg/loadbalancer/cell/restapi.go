// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/go-openapi/runtime/middleware"

	serviceapi "github.com/cilium/cilium/api/v1/server/restapi/service"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type serviceRestApiHandlerOut struct {
	cell.Out

	GetServiceHandler serviceapi.GetServiceHandler
}

func newServiceRestApiHandler(log *slog.Logger, db *statedb.DB, fes statedb.Table[*loadbalancer.Frontend]) serviceRestApiHandlerOut {
	return serviceRestApiHandlerOut{
		GetServiceHandler: &getServiceHandler{
			log: log,
			db:  db,
			fes: fes,
		},
	}
}

type getServiceHandler struct {
	log *slog.Logger
	db  *statedb.DB
	fes statedb.Table[*loadbalancer.Frontend]
}

func (h *getServiceHandler) Handle(params serviceapi.GetServiceParams) middleware.Responder {
	h.log.Debug(
		"GET /service request",
		logfields.Params, params,
	)
	return serviceapi.NewGetServiceOK().WithPayload(
		statedb.Collect(
			statedb.Map(
				h.fes.All(h.db.ReadTxn()),
				(*loadbalancer.Frontend).ToModel,
			),
		),
	)
}
