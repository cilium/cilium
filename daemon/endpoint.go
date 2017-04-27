// Copyright 2016-2017 Authors of Cilium
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
	"os"
	"sync"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/apierror"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"

	"github.com/go-openapi/runtime/middleware"
)

func (d *Daemon) lookupCiliumEndpoint(id uint16) *endpoint.Endpoint {
	if ep, ok := d.endpoints[id]; ok {
		return ep
	}
	return nil
}

func (d *Daemon) lookupDockerEndpoint(id string) *endpoint.Endpoint {
	i := endpoint.NewID(endpoint.DockerEndpointPrefix, id)
	if ep, ok := d.endpointsAux[i]; ok {
		return ep
	}
	return nil
}

func (d *Daemon) lookupDockerID(id string) *endpoint.Endpoint {
	i := endpoint.NewID(endpoint.ContainerIdPrefix, id)
	if ep, ok := d.endpointsAux[i]; ok {
		return ep
	}
	return nil
}

func (d *Daemon) linkContainerID(ep *endpoint.Endpoint) {
	id := endpoint.NewID(endpoint.ContainerIdPrefix, ep.DockerID)
	d.endpointsAux[id] = ep
}

// insertEndpoint inserts the ep in the endpoints map. To be used with endpointsMU locked.
func (d *Daemon) insertEndpoint(ep *endpoint.Endpoint) {
	ep.Mutex.Lock()
	defer ep.Mutex.Unlock()
	d.endpoints[ep.ID] = ep

	if ep.DockerID != "" {
		d.linkContainerID(ep)
	}

	if ep.DockerEndpointID != "" {
		id := endpoint.NewID(endpoint.DockerEndpointPrefix, ep.DockerEndpointID)
		d.endpointsAux[id] = ep
	}
}

func (d *Daemon) removeEndpoint(ep *endpoint.Endpoint) {
	delete(d.endpoints, ep.ID)

	if ep.DockerID != "" {
		id := endpoint.NewID(endpoint.ContainerIdPrefix, ep.DockerID)
		delete(d.endpointsAux, id)
	}

	if ep.DockerEndpointID != "" {
		id := endpoint.NewID(endpoint.DockerEndpointPrefix, ep.DockerID)
		delete(d.endpointsAux, id)
	}
}

// Sets the given secLabel on the endpoint with the given endpointID. Returns a pointer of
// a copy endpoint if the endpoint was found, nil otherwise.
func (d *Daemon) SetEndpointIdentity(ep *endpoint.Endpoint, dockerID, dockerEPID string, labels *policy.Identity) {
	setIfNotEmpty := func(receiver *string, provider string) {
		if receiver != nil && *receiver == "" && provider != "" {
			*receiver = provider
		}
	}

	ep.Mutex.Lock()
	setIfNotEmpty(&ep.DockerID, dockerID)
	setIfNotEmpty(&ep.DockerEndpointID, dockerEPID)
	ep.Mutex.Unlock()

	ep.SetIdentity(d, labels)
}

func (d *Daemon) lookupEndpoint(id string) (*endpoint.Endpoint, *apierror.APIError) {
	prefix, eid, err := endpoint.ParseID(id)
	if err != nil {
		return nil, apierror.Error(GetEndpointIDInvalidCode, err)
	}

	switch prefix {
	case endpoint.CiliumLocalIdPrefix:
		n, _ := endpoint.ParseCiliumID(id)
		return d.lookupCiliumEndpoint(uint16(n)), nil
	case endpoint.CiliumGlobalIdPrefix:
		return nil, apierror.New(GetEndpointIDInvalidCode,
			"Unsupported id format for now")
	case endpoint.ContainerIdPrefix:
		return d.lookupDockerID(eid), nil
	case endpoint.DockerEndpointPrefix:
		return d.lookupDockerEndpoint(eid), nil
	default:
		return nil, apierror.New(GetEndpointIDInvalidCode, "Unknown endpoint prefix %s", prefix)
	}
}

func (d *Daemon) EndpointExists(id string) bool {
	d.endpointsMU.RLock()
	ep, err := d.lookupEndpoint(id)
	d.endpointsMU.RUnlock()
	return err == nil && ep != nil
}

type getEndpoint struct {
	d *Daemon
}

func NewGetEndpointHandler(d *Daemon) GetEndpointHandler {
	return &getEndpoint{d: d}
}

func (h *getEndpoint) Handle(params GetEndpointParams) middleware.Responder {
	log.Debugf("GET /endpoint request: %+v", params)

	var wg sync.WaitGroup
	i := 0
	h.d.endpointsMU.RLock()
	eps := make([]*models.Endpoint, len(h.d.endpoints))
	wg.Add(len(h.d.endpoints))
	for k := range h.d.endpoints {
		go func(wg *sync.WaitGroup, i int, ep *endpoint.Endpoint) {
			eps[i] = ep.GetModel()
			wg.Done()
		}(&wg, i, h.d.endpoints[k])
		i++
	}
	h.d.endpointsMU.RUnlock()
	wg.Wait()

	return NewGetEndpointOK().WithPayload(eps)
}

type getEndpointID struct {
	d *Daemon
}

func NewGetEndpointIDHandler(d *Daemon) GetEndpointIDHandler {
	return &getEndpointID{d: d}
}

func (h *getEndpointID) Handle(params GetEndpointIDParams) middleware.Responder {
	log.Debugf("GET /endpoint/{id} request: %+v", params.ID)

	h.d.endpointsMU.RLock()
	ep, err := h.d.lookupEndpoint(params.ID)
	h.d.endpointsMU.RUnlock()
	if err != nil {
		return err
	} else if ep == nil {
		return NewGetEndpointIDNotFound()
	} else {
		return NewGetEndpointIDOK().WithPayload(ep.GetModel())
	}
}

type putEndpointID struct {
	d *Daemon
}

func NewPutEndpointIDHandler(d *Daemon) PutEndpointIDHandler {
	return &putEndpointID{d: d}
}

func (h *putEndpointID) Handle(params PutEndpointIDParams) middleware.Responder {
	log.Debugf("PUT /endpoint/{id} request: %+v", params)

	epTemplate := params.Endpoint
	if n, err := endpoint.ParseCiliumID(params.ID); err != nil {
		return apierror.Error(PutEndpointIDInvalidCode, err)
	} else if n != epTemplate.ID {
		return apierror.New(PutEndpointIDInvalidCode,
			"ID parameter does not match ID in endpoint parameter")
	} else if epTemplate.ID == 0 {
		return apierror.New(PutEndpointIDInvalidCode,
			"endpoint ID cannot be 0")
	}

	ep, err := endpoint.NewEndpointFromChangeModel(epTemplate)
	if err != nil {
		return apierror.Error(PutEndpointIDInvalidCode, err)
	}

	ep.SetDefaultOpts(h.d.conf.Opts)

	h.d.endpointsMU.Lock()
	defer h.d.endpointsMU.Unlock()

	oldEp, err2 := h.d.lookupEndpoint(params.ID)
	if err2 != nil {
		return err2
	} else if oldEp != nil {
		return NewPutEndpointIDExists()
	}

	if err := ep.CreateDirectory(); err != nil {
		log.Warningf("Aborting endpoint join: %s", err)
		return apierror.Error(PutEndpointIDFailedCode, err)
	}

	if err := ep.RegenerateIfReady(h.d); err != nil {
		ep.RemoveDirectory()
		return apierror.Error(PatchEndpointIDFailedCode, err)
	}

	h.d.insertEndpoint(ep)

	return NewPutEndpointIDCreated()
}

type patchEndpointID struct {
	d *Daemon
}

func NewPatchEndpointIDHandler(d *Daemon) PatchEndpointIDHandler {
	return &patchEndpointID{d: d}
}

func (h *patchEndpointID) Handle(params PatchEndpointIDParams) middleware.Responder {
	log.Debugf("PATCH /endpoint/{id} %+v", params)

	epTemplate := params.Endpoint

	// Validate the template. Assignment afterwards is atomic.
	newEp, err2 := endpoint.NewEndpointFromChangeModel(epTemplate)
	if err2 != nil {
		return apierror.Error(PutEndpointIDInvalidCode, err2)
	}

	h.d.endpointsMU.RLock()
	ep, err := h.d.lookupEndpoint(params.ID)
	h.d.endpointsMU.RUnlock()
	if err != nil {
		return err
	}
	if ep == nil {
		return NewPatchEndpointIDNotFound()
	}

	changed := false

	// FIXME: Support changing these?
	//  - container ID
	//  - docker network id
	//  - docker endpoint id
	//
	//  Support arbitrary changes? Support only if unset?

	ep.Mutex.Lock()
	if epTemplate.InterfaceIndex != 0 {
		ep.IfIndex = int(epTemplate.InterfaceIndex)
		changed = true
	}

	if epTemplate.InterfaceName != "" {
		ep.IfName = epTemplate.InterfaceName
		changed = true
	}

	if epTemplate.State != "" {
		// FIXME: Validate
		ep.State = string(epTemplate.State)
		changed = true
	}

	if epTemplate.Mac != "" {
		ep.LXCMAC = newEp.LXCMAC
		changed = true
	}

	if epTemplate.HostMac != "" {
		ep.NodeMAC = newEp.NodeMAC
		changed = true
	}

	if epTemplate.Addressing != nil {
		if ip := epTemplate.Addressing.IPV6; ip != "" {
			ep.IPv6 = newEp.IPv6
			changed = true
		}

		if ip := epTemplate.Addressing.IPV4; ip != "" {
			ep.IPv4 = newEp.IPv4
			changed = true
		}
	}

	// If desired state is waiting-for-identity but identity is already
	// known, bump it to ready state immediately to force re-generation
	if ep.State == endpoint.StateWaitingForIdentity && ep.SecLabel != nil {
		ep.State = endpoint.StateReady
		changed = true
	}
	ep.Mutex.Unlock()

	if changed {
		if err := ep.RegenerateIfReady(h.d); err != nil {
			return apierror.Error(PatchEndpointIDFailedCode, err)
		}

		// FIXME: Special return code to indicate regeneration happened?
	}

	return NewPatchEndpointIDOK()
}

// deleteEndpoint must be called with d.endpointsMU locked.
func (d *Daemon) deleteEndpoint(ep *endpoint.Endpoint) int {
	errors := 0
	ep.Mutex.Lock()
	defer ep.Mutex.Unlock()
	ep.LeaveLocked(d)

	if err := d.conf.LXCMap.DeleteElement(ep); err != nil {
		log.Warningf("Unable to remove endpoint from map: %s", err)
		errors++
	}

	if ep.Consumable != nil {
		ep.Consumable.RemoveMap(ep.PolicyMap)
	}

	// Remove policy BPF map
	if err := os.RemoveAll(ep.PolicyMapPathLocked()); err != nil {
		log.Warningf("Unable to remove policy map file (%s): %s", ep.PolicyMapPathLocked(), err)
		errors++
	}

	// Remove IPv6 connection tracking map
	if err := os.RemoveAll(ep.Ct6MapPathLocked()); err != nil {
		log.Warningf("Unable to remove IPv6 CT map file (%s): %s", ep.Ct6MapPathLocked(), err)
		errors++
	}

	// Remove IPv4 connection tracking map
	if err := os.RemoveAll(ep.Ct4MapPathLocked()); err != nil {
		log.Warningf("Unable to remove IPv4 CT map file (%s): %s", ep.Ct4MapPathLocked(), err)
		errors++
	}

	d.removeEndpoint(ep)

	if !d.conf.IPv4Disabled {
		if err := d.ReleaseIP(ep.IPv4.IP()); err != nil {
			log.Warningf("error while releasing IPv4 %s: %s", ep.IPv4.IP(), err)
			errors++
		}
	}

	if err := d.ReleaseIP(ep.IPv6.IP()); err != nil {
		log.Warningf("error while releasing IPv6 %s: %s", ep.IPv6.IP(), err)
		errors++
	}

	return errors
}

func (d *Daemon) DeleteEndpoint(id string) (int, *apierror.APIError) {
	d.endpointsMU.Lock()
	defer d.endpointsMU.Unlock()

	if ep, err := d.lookupEndpoint(id); err != nil {
		return 0, err
	} else if ep == nil {
		return 0, apierror.New(DeleteEndpointIDNotFoundCode, "endpoint not found")
	} else {
		return d.deleteEndpoint(ep), nil
	}
}

type deleteEndpointID struct {
	daemon *Daemon
}

func NewDeleteEndpointIDHandler(d *Daemon) DeleteEndpointIDHandler {
	return &deleteEndpointID{daemon: d}
}

func (h *deleteEndpointID) Handle(params DeleteEndpointIDParams) middleware.Responder {
	log.Debugf("DELETE /endpoint/{id} %+v", params)

	d := h.daemon
	if nerr, err := d.DeleteEndpoint(params.ID); err != nil {
		return err
	} else if nerr > 0 {
		return NewDeleteEndpointIDErrors().WithPayload(int64(nerr))
	} else {
		return NewDeleteEndpointIDOK()
	}
}

// EndpointUpdate updates the given endpoint and regenerates the endpoint
func (d *Daemon) EndpointUpdate(id string, opts models.ConfigurationMap) *apierror.APIError {
	d.endpointsMU.RLock()
	ep, err := d.lookupEndpoint(id)
	d.endpointsMU.RUnlock()
	if err != nil {
		return err
	}
	if ep != nil {
		d.invalidateCache()
		if err := ep.Update(d, opts); err != nil {
			switch err.(type) {
			case endpoint.UpdateValidationError:
				return apierror.Error(PatchEndpointIDConfigInvalidCode, err)
			default:
				return apierror.Error(PatchEndpointIDConfigFailedCode, err)
			}
		}
	} else {
		return apierror.New(PatchEndpointIDConfigNotFoundCode, "endpoint %s not found", id)
	}

	return nil
}

type patchEndpointIDConfig struct {
	daemon *Daemon
}

func NewPatchEndpointIDConfigHandler(d *Daemon) PatchEndpointIDConfigHandler {
	return &patchEndpointIDConfig{daemon: d}
}

func (h *patchEndpointIDConfig) Handle(params PatchEndpointIDConfigParams) middleware.Responder {
	log.Debugf("PATCH /endpoint/{id}/config %+v", params)

	d := h.daemon
	if err := d.EndpointUpdate(params.ID, params.Configuration); err != nil {
		return err
	}

	return NewPatchEndpointIDConfigOK()
}

type getEndpointIDConfig struct {
	daemon *Daemon
}

func NewGetEndpointIDConfigHandler(d *Daemon) GetEndpointIDConfigHandler {
	return &getEndpointIDConfig{daemon: d}
}

func (h *getEndpointIDConfig) Handle(params GetEndpointIDConfigParams) middleware.Responder {
	log.Debugf("GET /endpoint/{id}/config %+v", params)

	d := h.daemon
	d.endpointsMU.RLock()
	ep, err := d.lookupEndpoint(params.ID)
	d.endpointsMU.RUnlock()
	if err != nil {
		return err
	} else if ep == nil {
		return NewGetEndpointIDConfigNotFound()
	} else {
		return NewGetEndpointIDConfigOK().WithPayload(ep.Opts.GetModel())
	}
}

type getEndpointIDLabels struct {
	daemon *Daemon
}

func NewGetEndpointIDLabelsHandler(d *Daemon) GetEndpointIDLabelsHandler {
	return &getEndpointIDLabels{daemon: d}
}

func (h *getEndpointIDLabels) Handle(params GetEndpointIDLabelsParams) middleware.Responder {
	log.Debugf("GET /endpoint/{id}/labels %+v", params)

	d := h.daemon
	d.endpointsMU.RLock()
	ep, err := d.lookupEndpoint(params.ID)
	d.endpointsMU.RUnlock()
	if err != nil {
		return err
	}
	if ep == nil {
		return NewGetEndpointIDLabelsNotFound()
	}

	ep.Mutex.RLock()
	dockerID := ep.DockerID
	ep.Mutex.RUnlock()

	d.containersMU.RLock()
	cont := d.containers[dockerID]
	d.containersMU.RUnlock()
	if cont == nil {
		return NewGetEndpointIDLabelsNotFound()
	}

	cont.Mutex.RLock()
	cfg := models.LabelConfiguration{
		Disabled:            cont.OpLabels.Disabled.GetModel(),
		Custom:              cont.OpLabels.Custom.GetModel(),
		OrchestrationSystem: cont.OpLabels.Orchestration.GetModel(),
	}
	cont.Mutex.RUnlock()

	return NewGetEndpointIDLabelsOK().WithPayload(&cfg)
}

// UpdateSecLabels add and deletes the given labels on given endpoint ID.
// The received `add` and `del` labels will be filtered with the valid label
// prefixes.
func (d *Daemon) UpdateSecLabels(id string, add, del labels.Labels) middleware.Responder {
	d.conf.ValidLabelPrefixesMU.RLock()
	addLabels := d.conf.ValidLabelPrefixes.FilterLabels(add)
	delLabels := d.conf.ValidLabelPrefixes.FilterLabels(del)
	d.conf.ValidLabelPrefixesMU.RUnlock()

	if len(addLabels) == 0 && len(delLabels) == 0 {
		return nil
	}

	d.endpointsMU.RLock()
	ep, err := d.lookupEndpoint(id)
	d.endpointsMU.RUnlock()
	if err != nil {
		return err
	}
	if ep == nil {
		return NewPutEndpointIDLabelsNotFound()
	}

	ep.Mutex.RLock()
	epDockerID := ep.DockerID
	ep.Mutex.RUnlock()

	d.containersMU.RLock()
	cont := d.containers[epDockerID]
	d.containersMU.RUnlock()
	if cont == nil {
		return NewPutEndpointIDLabelsNotFound()
	}

	cont.Mutex.RLock()
	oldLabels := cont.OpLabels.DeepCopy()
	cont.Mutex.RUnlock()

	if len(delLabels) > 0 {
		for k := range delLabels {
			// The change request is accepted if the label is on
			// any of the lists. If the label is already disabled,
			// we will simply ignore that change.
			if oldLabels.Orchestration[k] != nil ||
				oldLabels.Custom[k] != nil ||
				oldLabels.Disabled[k] != nil {
				break
			}

			return apierror.New(PutEndpointIDLabelsLabelNotFoundCode,
				"label %s not found", k)
		}
	}

	if len(addLabels) > 0 {
		for k, v := range addLabels {
			if oldLabels.Disabled[k] != nil {
				oldLabels.Disabled[k] = nil
				oldLabels.Orchestration[k] = v
			} else if oldLabels.Orchestration[k] == nil {
				oldLabels.Custom[k] = v
			}
		}
	}

	if len(delLabels) > 0 {
		for k, v := range delLabels {
			if oldLabels.Orchestration[k] != nil {
				delete(oldLabels.Orchestration, k)
				oldLabels.Disabled[k] = v
			}

			if oldLabels.Custom[k] != nil {
				delete(oldLabels.Custom, k)
			}
		}
	}

	identity, newHash, err2 := d.updateContainerIdentity(cont.ID, cont.LabelsHash, oldLabels)
	if err2 != nil {
		return apierror.Error(PutEndpointIDLabelsUpdateFailedCode, err2)
	}
	cont.Mutex.Lock()
	cont.LabelsHash = newHash
	cont.OpLabels = *oldLabels
	contID := cont.ID
	cont.Mutex.Unlock()

	// FIXME: Undo identity update?

	d.endpointsMU.RLock()
	ep, _ = d.lookupEndpoint(id)
	d.endpointsMU.RUnlock()
	if ep == nil {
		return NewPutEndpointIDLabelsNotFound()
	}
	containerFound := false

	d.containersMU.RLock()
	if d.containers[epDockerID] != nil {
		containerFound = true
	}
	d.containersMU.RUnlock()

	if !containerFound {
		return NewPutEndpointIDLabelsNotFound()
	}

	d.SetEndpointIdentity(ep, contID, "", identity)

	ep.Regenerate(d)

	return nil
}

type putEndpointIDLabels struct {
	daemon *Daemon
}

func NewPutEndpointIDLabelsHandler(d *Daemon) PutEndpointIDLabelsHandler {
	return &putEndpointIDLabels{daemon: d}
}

func (h *putEndpointIDLabels) Handle(params PutEndpointIDLabelsParams) middleware.Responder {
	d := h.daemon

	log.Debugf("PUT /endpoint/{id}/labels %+v", params)

	mod := params.Configuration
	add := labels.NewLabelsFromModel(mod.Add)
	del := labels.NewLabelsFromModel(mod.Delete)

	err := d.UpdateSecLabels(params.ID, add, del)
	if err != nil {
		return err
	}

	return NewPutEndpointIDLabelsOK()
}
