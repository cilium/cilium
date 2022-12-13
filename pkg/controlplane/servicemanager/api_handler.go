// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package servicemanager

import (
	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/service"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/go-openapi/runtime/middleware"
)

var APIHandlersCell = cell.Module(
	"service-rest-api",
	"Handler for the services REST API",

	cell.Provide(newAPIHandler),
)

type apiHandlersOut struct {
	cell.Out

	PutServiceIDHandler
	DeleteServiceIDHandler
	GetServiceIDHandler
	GetServiceHandler
}

func newAPIHandler(mgr ServiceManager) apiHandlersOut {
	handle := mgr.NewHandle("api")
	handle.Synchronized()
	return apiHandlersOut{
		PutServiceIDHandler:    &putServiceID{handle},
		DeleteServiceIDHandler: &deleteServiceID{handle},
		GetServiceHandler:      &getService{handle},
		GetServiceIDHandler:    &getServiceID{handle},
	}
}

type putServiceID struct {
	svc ServiceHandle
}

// XXX take as dep
var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "servicemanager")

func (h *putServiceID) Handle(params PutServiceIDParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("PUT /service/{id} request")

	/* TODO WUT
	if params.Config.ID == 0 {
		if !params.Config.UpdateServices {
			return api.Error(PutServiceIDFailureCode, fmt.Errorf("invalid service ID 0"))
		}
		backends := []*loadbalancer.Backend{}
		for _, v := range params.Config.BackendAddresses {
			b, err := loadbalancer.NewBackendFromBackendModel(v)
			if err != nil {
				return api.Error(PutServiceIDInvalidBackendCode, err)
			}
			backends = append(backends, b)
		}
		if err := h.svc.UpdateBackendsState(backends); err != nil {
			return api.Error(PutServiceIDUpdateBackendFailureCode, err)
		}
		return NewPutServiceIDOK()
	}*/

	f, err := loadbalancer.NewL3n4AddrFromModel(params.Config.FrontendAddress)
	if err != nil {
		return api.Error(PutServiceIDInvalidFrontendCode, err)
	}

	frontend := loadbalancer.L3n4AddrID{
		L3n4Addr: *f,
		ID:       loadbalancer.ID(params.Config.ID),
	}
	backends := []*loadbalancer.Backend{}
	for _, v := range params.Config.BackendAddresses {
		b, err := loadbalancer.NewBackendFromBackendModel(v)
		if err != nil {
			return api.Error(PutServiceIDInvalidBackendCode, err)
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

	fe := &Frontend{
		Name:                loadbalancer.ServiceName{Name: svcName, Namespace: svcNamespace},
		Type:                svcType,
		Address:             frontend.L3n4Addr,
		TrafficPolicy:       svcTrafficPolicy,
		HealthCheckNodePort: svcHealthCheckNodePort,
		// ...
	}
	h.svc.Upsert(fe, backends)

	/*

		p := &loadbalancer.SVC{
			Name:                loadbalancer.ServiceName{Name: svcName, Namespace: svcNamespace},
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
	*/

	return NewPutServiceIDOK()
}

type deleteServiceID struct {
	svc ServiceHandle
}

func (h *deleteServiceID) Handle(params DeleteServiceIDParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("DELETE /service/{id} request")

	panic("TBD")
	/*
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
		}*/
}

type getServiceID struct {
	svc ServiceHandle
}

func (h *getServiceID) Handle(params GetServiceIDParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /service/{id} request")

	panic("TBD")
	/*
		if svc, ok := h.svc.GetDeepCopyServiceByID(loadbalancer.ServiceID(params.ID)); ok {
			return NewGetServiceIDOK().WithPayload(svc.GetModel())
		}
		return NewGetServiceIDNotFound()*/
}

type getService struct {
	svc ServiceHandle
}

func (h *getService) Handle(params GetServiceParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /service request")
	list := getServiceList(h.svc)
	return NewGetServiceOK().WithPayload(list)
}

func getServiceList(svc ServiceHandle) []*models.Service {
	it := svc.Iter()
	list := []*models.Service{}
	for fe, bes, ok := it.Next(); ok; fe, bes, ok = it.Next() {
		m := &models.Service{}
		spec := &models.ServiceSpec{}
		m.Spec = spec
		spec.FrontendAddress = fe.Address.GetModel()
		spec.BackendAddresses = make([]*models.BackendAddress, len(bes))
		for i, be := range bes {
			spec.BackendAddresses[i] = be.GetBackendModel()
		}
		spec.Flags = &models.ServiceSpecFlags{
			Type:                string(fe.Type),
			TrafficPolicy:       string(fe.TrafficPolicy),
			NatPolicy:           string(fe.NatPolicy),
			HealthCheckNodePort: fe.HealthCheckNodePort,
			Name:                fe.Name.Name,
			Namespace:           fe.Name.Namespace,
		}
		m.Status = &models.ServiceStatus{
			Realized: spec,
		}
		list = append(list, m)
		// TODO rest
	}
	return list
}
