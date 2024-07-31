// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"fmt"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/go-openapi/runtime/middleware"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	serviceapi "github.com/cilium/cilium/api/v1/server/restapi/service"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var warnIdTypeDeprecationOnce sync.Once

type serviceRestApiHandlerParams struct {
	cell.In

	Logger         logrus.FieldLogger
	ServiceManager ServiceManager
}

type serviceRestApiHandlerOut struct {
	cell.Out

	GetServiceIDHandler    serviceapi.GetServiceIDHandler
	PutServiceIDHandler    serviceapi.PutServiceIDHandler
	DeleteServiceIDHandler serviceapi.DeleteServiceIDHandler

	GetServiceHandler serviceapi.GetServiceHandler
}

func newServiceRestApiHandler(params serviceRestApiHandlerParams) serviceRestApiHandlerOut {
	return serviceRestApiHandlerOut{
		GetServiceIDHandler: &getServiceIDHandler{
			logger:         params.Logger,
			serviceManager: params.ServiceManager,
		},
		PutServiceIDHandler: &putServiceIDHandler{
			logger:         params.Logger,
			serviceManager: params.ServiceManager,
		},
		DeleteServiceIDHandler: &deleteServiceIDHandler{
			logger:         params.Logger,
			serviceManager: params.ServiceManager,
		},
		GetServiceHandler: &getServiceHandler{
			logger:         params.Logger,
			serviceManager: params.ServiceManager,
		},
	}
}

type putServiceIDHandler struct {
	logger         logrus.FieldLogger
	serviceManager ServiceManager
}

func (h *putServiceIDHandler) Handle(params serviceapi.PutServiceIDParams) middleware.Responder {
	warnIdTypeDeprecation(h.logger)

	h.logger.WithField(logfields.Params, logfields.Repr(params)).Debug("PUT /service/{id} request")

	if params.Config.ID == 0 {
		if !params.Config.UpdateServices {
			return api.Error(serviceapi.PutServiceIDFailureCode, fmt.Errorf("invalid service ID 0"))
		}
		backends := []*loadbalancer.Backend{}
		for _, v := range params.Config.BackendAddresses {
			b, err := loadbalancer.NewBackendFromBackendModel(v)
			if err != nil {
				return api.Error(serviceapi.PutServiceIDInvalidBackendCode, err)
			}
			backends = append(backends, b)
		}
		if _, err := h.serviceManager.UpdateBackendsState(backends); err != nil {
			return api.Error(serviceapi.PutServiceIDUpdateBackendFailureCode, err)
		}
		return serviceapi.NewPutServiceIDOK()
	}

	f, err := loadbalancer.NewL3n4AddrFromModel(params.Config.FrontendAddress)
	if err != nil {
		return api.Error(serviceapi.PutServiceIDInvalidFrontendCode, err)
	}

	frontend := loadbalancer.L3n4AddrID{
		L3n4Addr: *f,
		ID:       loadbalancer.ID(params.Config.ID),
	}
	backends := []*loadbalancer.Backend{}
	for _, v := range params.Config.BackendAddresses {
		b, err := loadbalancer.NewBackendFromBackendModel(v)
		if err != nil {
			return api.Error(serviceapi.PutServiceIDInvalidBackendCode, err)
		}
		backends = append(backends, b)
	}

	var svcType loadbalancer.SVCType
	switch params.Config.Flags.Type {
	case models.ServiceSpecFlagsTypeExternalIPs:
		svcType = loadbalancer.SVCTypeExternalIPs
	case models.ServiceSpecFlagsTypeNodePort:
		svcType = loadbalancer.SVCTypeNodePort
	case models.ServiceSpecFlagsTypeLoadBalancer:
		svcType = loadbalancer.SVCTypeLoadBalancer
	case models.ServiceSpecFlagsTypeHostPort:
		svcType = loadbalancer.SVCTypeHostPort
	case models.ServiceSpecFlagsTypeLocalRedirect:
		svcType = loadbalancer.SVCTypeLocalRedirect
	default:
		svcType = loadbalancer.SVCTypeClusterIP
	}

	var svcExtTrafficPolicy loadbalancer.SVCTrafficPolicy
	switch params.Config.Flags.ExtTrafficPolicy {
	case models.ServiceSpecFlagsExtTrafficPolicyLocal:
		svcExtTrafficPolicy = loadbalancer.SVCTrafficPolicyLocal
	default:
		svcExtTrafficPolicy = loadbalancer.SVCTrafficPolicyCluster
	}

	var svcIntTrafficPolicy loadbalancer.SVCTrafficPolicy
	switch params.Config.Flags.IntTrafficPolicy {
	case models.ServiceSpecFlagsIntTrafficPolicyLocal:
		svcIntTrafficPolicy = loadbalancer.SVCTrafficPolicyLocal
	default:
		svcIntTrafficPolicy = loadbalancer.SVCTrafficPolicyCluster
	}

	svcHealthCheckNodePort := params.Config.Flags.HealthCheckNodePort

	var svcName, svcNamespace, svcCluster string
	if params.Config.Flags != nil {
		svcName = params.Config.Flags.Name
		svcNamespace = params.Config.Flags.Namespace
		svcCluster = params.Config.Flags.Cluster
	}

	p := &loadbalancer.SVC{
		Name:                loadbalancer.ServiceName{Name: svcName, Namespace: svcNamespace, Cluster: svcCluster},
		Type:                svcType,
		Frontend:            frontend,
		Backends:            backends,
		ExtTrafficPolicy:    svcExtTrafficPolicy,
		IntTrafficPolicy:    svcIntTrafficPolicy,
		HealthCheckNodePort: svcHealthCheckNodePort,
	}
	created, id, err := h.serviceManager.UpsertService(p)
	if err == nil && id != frontend.ID {
		return api.Error(serviceapi.PutServiceIDInvalidFrontendCode,
			fmt.Errorf("the service provided is already registered with ID %d, please use that ID instead of %d",
				id, frontend.ID))
	} else if err != nil {
		return api.Error(serviceapi.PutServiceIDFailureCode, err)
	} else if created {
		return serviceapi.NewPutServiceIDCreated()
	} else {
		return serviceapi.NewPutServiceIDOK()
	}
}

type deleteServiceIDHandler struct {
	logger         logrus.FieldLogger
	serviceManager ServiceManager
}

func (h *deleteServiceIDHandler) Handle(params serviceapi.DeleteServiceIDParams) middleware.Responder {
	warnIdTypeDeprecation(h.logger)

	h.logger.WithField(logfields.Params, logfields.Repr(params)).Debug("DELETE /service/{id} request")

	found, err := h.serviceManager.DeleteServiceByID(loadbalancer.ServiceID(params.ID))
	switch {
	case err != nil:
		h.logger.WithError(err).WithField(logfields.ServiceID, params.ID).
			Warn("DELETE /service/{id}: error deleting service")
		return api.Error(serviceapi.DeleteServiceIDFailureCode, err)
	case !found:
		return serviceapi.NewDeleteServiceIDNotFound()
	default:
		return serviceapi.NewDeleteServiceIDOK()
	}
}

type getServiceIDHandler struct {
	logger         logrus.FieldLogger
	serviceManager ServiceManager
}

func (h *getServiceIDHandler) Handle(params serviceapi.GetServiceIDParams) middleware.Responder {
	warnIdTypeDeprecation(h.logger)

	h.logger.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /service/{id} request")

	if svc, ok := h.serviceManager.GetDeepCopyServiceByID(loadbalancer.ServiceID(params.ID)); ok {
		return serviceapi.NewGetServiceIDOK().WithPayload(svc.GetModel())
	}
	return serviceapi.NewGetServiceIDNotFound()
}

type getServiceHandler struct {
	logger         logrus.FieldLogger
	serviceManager ServiceManager
}

func (h *getServiceHandler) Handle(params serviceapi.GetServiceParams) middleware.Responder {
	h.logger.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /service request")
	list := GetServiceModelList(h.serviceManager)
	return serviceapi.NewGetServiceOK().WithPayload(list)
}

func warnIdTypeDeprecation(logger logrus.FieldLogger) {
	warnIdTypeDeprecationOnce.Do(func() {
		logger.Warning("Deprecation: The type of {id} in /service/{id} will change from int to string in v1.14")
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
