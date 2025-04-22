// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"log/slog"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	serviceapi "github.com/cilium/cilium/api/v1/server/restapi/service"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var warnIdTypeDeprecationOnce sync.Once

type serviceRestApiHandlerParams struct {
	cell.In

	Logger         *slog.Logger
	ServiceManager ServiceManager
}

type serviceRestApiHandlerOut struct {
	cell.Out

	GetServiceIDHandler serviceapi.GetServiceIDHandler
	GetServiceHandler   serviceapi.GetServiceHandler
}

func newServiceRestApiHandler(params serviceRestApiHandlerParams) serviceRestApiHandlerOut {
	return serviceRestApiHandlerOut{
		GetServiceIDHandler: &getServiceIDHandler{
			logger:         params.Logger,
			serviceManager: params.ServiceManager,
		},
		GetServiceHandler: &getServiceHandler{
			logger:         params.Logger,
			serviceManager: params.ServiceManager,
		},
	}
}

type getServiceIDHandler struct {
	logger         *slog.Logger
	serviceManager ServiceManager
}

func (h *getServiceIDHandler) Handle(params serviceapi.GetServiceIDParams) middleware.Responder {
	warnIdTypeDeprecation(h.logger)

	h.logger.Debug(
		"GET /service/{id} request",
		logfields.Params, params,
	)

	if svc, ok := h.serviceManager.GetDeepCopyServiceByID(loadbalancer.ServiceID(params.ID)); ok {
		return serviceapi.NewGetServiceIDOK().WithPayload(svc.GetModel())
	}
	return serviceapi.NewGetServiceIDNotFound()
}

type getServiceHandler struct {
	logger         *slog.Logger
	serviceManager ServiceManager
}

func (h *getServiceHandler) Handle(params serviceapi.GetServiceParams) middleware.Responder {
	h.logger.Debug(
		"GET /service request",
		logfields.Params, params,
	)
	list := GetServiceModelList(h.serviceManager)
	return serviceapi.NewGetServiceOK().WithPayload(list)
}

func warnIdTypeDeprecation(logger *slog.Logger) {
	warnIdTypeDeprecationOnce.Do(func() {
		logger.Warn("Deprecation: The type of {id} in /service/{id} will change from int to string in v1.14")
	})
}

func GetServiceModelList(svc ServiceManager) []*models.Service {
	svcs := svc.GetDeepCopyServices()
	list := make([]*models.Service, 0, len(svcs))
	for _, v := range svcs {
		list = append(list, v.GetModel())
	}
	return list
}
