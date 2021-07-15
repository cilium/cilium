// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2020 Authors of Cilium

package cmd

import (
	"fmt"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/service"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/service"

	"github.com/go-openapi/runtime/middleware"
)

type putServiceID struct {
	svc *service.Service
}

func NewPutServiceIDHandler(svc *service.Service) PutServiceIDHandler {
	return &putServiceID{svc: svc}
}

func (h *putServiceID) Handle(params PutServiceIDParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("PUT /service/{id} request")

	if params.Config.ID == 0 {
		return api.Error(PutServiceIDFailureCode, fmt.Errorf("invalid service ID 0"))
	}

	f, err := loadbalancer.NewL3n4AddrFromModel(params.Config.FrontendAddress)
	if err != nil {
		return api.Error(PutServiceIDInvalidFrontendCode, err)
	}

	frontend := loadbalancer.L3n4AddrID{
		L3n4Addr: *f,
		ID:       loadbalancer.ID(params.Config.ID),
	}
	backends := []loadbalancer.Backend{}
	for _, v := range params.Config.BackendAddresses {
		b, err := loadbalancer.NewBackendFromBackendModel(v)
		if err != nil {
			return api.Error(PutServiceIDInvalidBackendCode, err)
		}
		backends = append(backends, *b)
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

	var svcTrafficPolicy loadbalancer.SVCTrafficPolicy
	switch params.Config.Flags.TrafficPolicy {
	case models.ServiceSpecFlagsTrafficPolicyLocal:
		svcTrafficPolicy = loadbalancer.SVCTrafficPolicyLocal
	default:
		svcTrafficPolicy = loadbalancer.SVCTrafficPolicyCluster
	}

	svcHealthCheckNodePort := params.Config.Flags.HealthCheckNodePort

	var svcName, svcNamespace string
	if params.Config.Flags != nil {
		svcName = params.Config.Flags.Name
		svcNamespace = params.Config.Flags.Namespace
	}

	p := &loadbalancer.SVC{
		Name:                svcName,
		Namespace:           svcNamespace,
		Type:                svcType,
		Frontend:            frontend,
		Backends:            backends,
		TrafficPolicy:       svcTrafficPolicy,
		HealthCheckNodePort: svcHealthCheckNodePort,
	}
	created, id, err := h.svc.UpsertService(p)
	if err == nil && id != frontend.ID {
		return api.Error(PutServiceIDInvalidFrontendCode,
			fmt.Errorf("the service provided is already registered with ID %d, please use that ID instead of %d",
				id, frontend.ID))
	} else if err != nil {
		return api.Error(PutServiceIDFailureCode, err)
	} else if created {
		return NewPutServiceIDCreated()
	} else {
		return NewPutServiceIDOK()
	}
}

type deleteServiceID struct {
	svc *service.Service
}

func NewDeleteServiceIDHandler(svc *service.Service) DeleteServiceIDHandler {
	return &deleteServiceID{svc: svc}
}

func (h *deleteServiceID) Handle(params DeleteServiceIDParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("DELETE /service/{id} request")

	found, err := h.svc.DeleteServiceByID(loadbalancer.ServiceID(params.ID))
	switch {
	case err != nil:
		log.WithError(err).WithField(logfields.ServiceID, params.ID).
			Warn("DELETE /service/{id}: error deleting service")
		return api.Error(DeleteServiceIDFailureCode, err)
	case !found:
		return NewDeleteServiceIDNotFound()
	default:
		return NewDeleteServiceIDOK()
	}
}

type getServiceID struct {
	svc *service.Service
}

func NewGetServiceIDHandler(svc *service.Service) GetServiceIDHandler {
	return &getServiceID{svc: svc}
}

func (h *getServiceID) Handle(params GetServiceIDParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /service/{id} request")

	if svc, ok := h.svc.GetDeepCopyServiceByID(loadbalancer.ServiceID(params.ID)); ok {
		return NewGetServiceIDOK().WithPayload(svc.GetModel())
	}
	return NewGetServiceIDNotFound()
}

type getService struct {
	svc *service.Service
}

func NewGetServiceHandler(svc *service.Service) GetServiceHandler {
	return &getService{svc: svc}
}

func (h *getService) Handle(params GetServiceParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /service request")
	list := getServiceList(h.svc)
	return NewGetServiceOK().WithPayload(list)
}

func getServiceList(svc *service.Service) []*models.Service {
	svcs := svc.GetDeepCopyServices()
	list := make([]*models.Service, 0, len(svcs))
	for _, v := range svcs {
		list = append(list, v.GetModel())
	}
	return list
}
