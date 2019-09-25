// Copyright 2016-2019 Authors of Cilium
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

package main

import (
	"fmt"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/service"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/svc"

	"github.com/go-openapi/runtime/middleware"
)

// SVCAdd is the public method to add services. We assume the ID provided is not in
// sync with the KVStore. If that's the, case the service won't be used and an error is
// returned to the caller.
//
// Returns true if service was created.
func (d *Daemon) SVCAdd(feL3n4Addr loadbalancer.L3n4AddrID, be []loadbalancer.LBBackEnd) (bool, error) {
	log.WithField(logfields.ServiceID, feL3n4Addr.String()).Debug("adding service")
	if feL3n4Addr.ID == 0 {
		return false, fmt.Errorf("invalid service ID 0")
	}

	created, id, err := d.svc.UpsertService(feL3n4Addr, be, svc.TypeClusterIP)
	if err == nil && id != feL3n4Addr.ID {
		return false,
			fmt.Errorf("the service provided is already registered with ID %d, please use that ID instead of %d",
				id, feL3n4Addr.ID)
	}

	return created, err
}

type putServiceID struct {
	d *Daemon
}

func NewPutServiceIDHandler(d *Daemon) PutServiceIDHandler {
	return &putServiceID{d: d}
}

func (h *putServiceID) Handle(params PutServiceIDParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("PUT /service/{id} request")

	f, err := loadbalancer.NewL3n4AddrFromModel(params.Config.FrontendAddress)
	if err != nil {
		return api.Error(PutServiceIDInvalidFrontendCode, err)
	}

	frontend := loadbalancer.L3n4AddrID{
		L3n4Addr: *f,
		ID:       loadbalancer.ID(params.Config.ID),
	}

	backends := []loadbalancer.LBBackEnd{}
	for _, v := range params.Config.BackendAddresses {
		b, err := loadbalancer.NewLBBackEndFromBackendModel(v)
		if err != nil {
			return api.Error(PutServiceIDInvalidBackendCode, err)
		}
		backends = append(backends, *b)
	}

	// FIXME
	// Add flag to indicate whether service should be registered in
	// global key value store

	if created, err := h.d.SVCAdd(frontend, backends); err != nil {
		return api.Error(PutServiceIDFailureCode, err)
	} else if created {
		return NewPutServiceIDCreated()
	} else {
		return NewPutServiceIDOK()
	}
}

type deleteServiceID struct {
	d *Daemon
}

func NewDeleteServiceIDHandler(d *Daemon) DeleteServiceIDHandler {
	return &deleteServiceID{d: d}
}

func (h *deleteServiceID) Handle(params DeleteServiceIDParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("DELETE /service/{id} request")

	found, err := h.d.svc.DeleteServiceByID(loadbalancer.ServiceID(params.ID))
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
	daemon *Daemon
}

func NewGetServiceIDHandler(d *Daemon) GetServiceIDHandler {
	return &getServiceID{daemon: d}
}

func (h *getServiceID) Handle(params GetServiceIDParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /service/{id} request")

	d := h.daemon

	if svc, ok := d.svc.GetDeepCopyServiceByID(loadbalancer.ServiceID(params.ID)); ok {
		return NewGetServiceIDOK().WithPayload(svc.GetModel())
	}
	return NewGetServiceIDNotFound()
}

type getService struct {
	d *Daemon
}

func NewGetServiceHandler(d *Daemon) GetServiceHandler {
	return &getService{d: d}
}

func (h *getService) Handle(params GetServiceParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /service request")
	list := h.d.GetServiceList()
	return NewGetServiceOK().WithPayload(list)
}

func openServiceMaps() error {
	// Removal of rr-seq maps can be removed in v1.8+.
	if err := bpf.UnpinMapIfExists("cilium_lb6_rr_seq_v2"); err != nil {
		return nil
	}
	if err := bpf.UnpinMapIfExists("cilium_lb4_rr_seq_v2"); err != nil {
		return nil
	}

	if option.Config.EnableIPv6 {
		if _, err := lbmap.Service6MapV2.OpenOrCreate(); err != nil {
			return err
		}
		if _, err := lbmap.Backend6Map.OpenOrCreate(); err != nil {
			return err
		}
		if _, err := lbmap.RevNat6Map.OpenOrCreate(); err != nil {
			return err
		}
	}

	if option.Config.EnableIPv4 {
		if _, err := lbmap.Service4MapV2.OpenOrCreate(); err != nil {
			return err
		}
		if _, err := lbmap.Backend4Map.OpenOrCreate(); err != nil {
			return err
		}
		if _, err := lbmap.RevNat4Map.OpenOrCreate(); err != nil {
			return err
		}
	}

	return nil
}

// GetServiceList returns list of services
func (d *Daemon) GetServiceList() []*models.Service {
	svcs := d.svc.GetDeepCopyServices()
	list := make([]*models.Service, 0, len(svcs))

	for _, v := range svcs {
		list = append(list, v.GetModel())
	}
	return list
}
