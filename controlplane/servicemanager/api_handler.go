// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package servicemanager

import (
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/service"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
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

	panic("TODO")
	/*
		f, err := loadbalancer.NewL3n4AddrFromModel(params.Config.FrontendAddress)
		if err != nil {
			return api.Error(PutServiceIDInvalidFrontendCode, err)
		}

		frontend := loadbalancer.L3n4AddrID{
			L3n4Addr: *f,
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

		idParts := strings.SplitN(params.ID, "/", 2)
		if len(idParts) != 2 {
			return api.Error(PutServiceIDInvalidBackendCode, fmt.Errorf("Invalid id: %q, expected <namespace>/<name>", params.ID))
		}
		var name loadbalancer.ServiceName
		name.Scope = loadbalancer.ScopeAPI // TODO or user definable?
		name.Namespace = idParts[0]
		name.Name = idParts[1]

		if params.Config.Flags != nil {
			ok := name.Namespace != params.Config.Flags.Namespace
			ok = ok || name.Name != params.Config.Flags.Name
			if !ok {
				panic("TODO deal with name mismatch in params.Config.Flags")
			}
		}*/

	/*
		fe := &lb.SVC{
			Name:                name,
			Type:                svcType,
			Address:             frontend.L3n4Addr,
			TrafficPolicy:       svcTrafficPolicy,
			HealthCheckNodePort: svcHealthCheckNodePort,
			// ...
		}
		h.svc.UpsertBackends(name, backends...)
		h.svc.UpsertFrontend(name, fe)
	*/
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
	panic("TODO")
	/*
	   list := []*models.Service{}

	   	for ev := range svc.Events(nil, true, nil) {
	   		beAddrs := []*models.BackendAddress{}
	   		ev.ForEachBackend(func(be Backend) {
	   			beAddrs = append(beAddrs, be.GetBackendModel())
	   		})

	   		ev.ForEachActiveFrontend(func(fe Frontend) {
	   			m := &models.Service{}
	   			spec := &models.ServiceSpec{}
	   			m.Spec = spec
	   			spec.ID = fe.Name.String()
	   			spec.FrontendAddress = fe.Address.GetModel()
	   			spec.BackendAddresses = beAddrs
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
	   		})
	   		// TODO rest
	   	}

	   return list
	*/
}
