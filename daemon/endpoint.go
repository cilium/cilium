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
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/policy"

	log "github.com/Sirupsen/logrus"
	"github.com/go-openapi/runtime/middleware"
)

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
	endpointmanager.Mutex.RLock()
	eps := make([]*models.Endpoint, len(endpointmanager.Endpoints))
	wg.Add(len(endpointmanager.Endpoints))
	for k := range endpointmanager.Endpoints {
		go func(wg *sync.WaitGroup, i int, ep *endpoint.Endpoint) {
			eps[i] = ep.GetModel()
			wg.Done()
		}(&wg, i, endpointmanager.Endpoints[k])
		i++
	}
	endpointmanager.Mutex.RUnlock()
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

	ep, err := endpointmanager.Lookup(params.ID)

	if err != nil {
		return apierror.Error(GetEndpointIDInvalidCode, err)
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

	addLabels := labels.ParseStringLabels(params.Endpoint.Labels)
	ep, err := endpoint.NewEndpointFromChangeModel(epTemplate, addLabels)
	if err != nil {
		return apierror.Error(PutEndpointIDInvalidCode, err)
	}

	ep.SetDefaultOpts(h.d.conf.Opts)
	ep.Opts.Set(endpoint.OptionPolicy, h.d.PolicyEnabled())

	endpointmanager.Mutex.Lock()
	defer endpointmanager.Mutex.Unlock()

	oldEp, err2 := endpointmanager.LookupLocked(params.ID)
	if err2 != nil {
		return apierror.Error(GetEndpointIDInvalidCode, err2)
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

	endpointmanager.Insert(ep)

	add := labels.NewLabelsFromModel(params.Endpoint.Labels)

	if len(add) > 0 {
		endpointmanager.Mutex.Unlock()
		errLabelsAdd := h.d.UpdateSecLabels(params.ID, add, labels.Labels{})
		endpointmanager.Mutex.Lock()
		if errLabelsAdd != nil {
			log.Errorf("Could not add labels %v while creating an ep %s due to %s", add, params.ID, errLabelsAdd)
			return errLabelsAdd
		}
	}

	ret := NewPutEndpointIDCreated()
	return ret
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
	addLabels := labels.ParseStringLabels(params.Endpoint.Labels)
	newEp, err2 := endpoint.NewEndpointFromChangeModel(epTemplate, addLabels)
	if err2 != nil {
		return apierror.Error(PutEndpointIDInvalidCode, err2)
	}

	ep, err := endpointmanager.Lookup(params.ID)
	if err != nil {
		return apierror.Error(GetEndpointIDInvalidCode, err)
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

// deleteEndpoint must be called with endpoint.Mutex locked.
func (d *Daemon) deleteEndpoint(ep *endpoint.Endpoint) int {
	ep.Mutex.Lock()
	defer ep.Mutex.Unlock()
	ep.LeaveLocked(d)

	sha256sum := ep.OpLabels.Enabled().SHA256Sum()
	if err := d.DeleteIdentityBySHA256(sha256sum, ep.StringID()); err != nil {
		log.Errorf("Error while deleting labels (SHA256SUM:%s) %+v: %s",
			sha256sum, ep.OpLabels.Enabled(), err)
	}
	errors := lxcmap.DeleteElement(ep)

	if ep.Consumable != nil {
		ep.Consumable.RemoveMap(ep.PolicyMap)
	}

	// Remove policy BPF map
	if err := os.RemoveAll(ep.PolicyMapPathLocked()); err != nil {
		log.Warningf("Unable to remove policy map file (%s): %s", ep.PolicyMapPathLocked(), err)
		errors++
	}

	// Remove calls BPF map
	if err := os.RemoveAll(ep.CallsMapPathLocked()); err != nil {
		log.Warningf("Unable to remove calls map file (%s): %s", ep.CallsMapPathLocked(), err)
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

	// Remove handle_policy() tail call entry for EP
	if ep.RemoveFromGlobalPolicyMap() != nil {
		log.Warningf("Unable to remove EP from global policy map!")
		errors++
	}

	endpointmanager.RemoveLocked(ep)

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
	endpointmanager.Mutex.Lock()
	defer endpointmanager.Mutex.Unlock()

	if ep, err := endpointmanager.LookupLocked(id); err != nil {
		return 0, apierror.Error(DeleteEndpointIDInvalidCode, err)
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
	ep, err := endpointmanager.Lookup(id)
	if err != nil {
		return apierror.Error(PatchEndpointIDInvalidCode, err)
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
		endpointmanager.UpdateReferences(ep)
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

	ep, err := endpointmanager.Lookup(params.ID)
	if err != nil {
		return apierror.Error(GetEndpointIDInvalidCode, err)
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
	ep, err := endpointmanager.Lookup(params.ID)
	if err != nil {
		return apierror.Error(GetEndpointIDInvalidCode, err)
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
		Disabled:            ep.OpLabels.Disabled.GetModel(),
		Custom:              ep.OpLabels.Custom.GetModel(),
		OrchestrationSystem: ep.OpLabels.Orchestration.GetModel(),
	}
	cont.Mutex.RUnlock()

	return NewGetEndpointIDLabelsOK().WithPayload(&cfg)
}

// UpdateSecLabels add and deletes the given labels on given endpoint ID.
// The received `add` and `del` labels will be filtered with the valid label
// prefixes.
// The `add` labels take precedence over `del` labels, this means if the same
// label is set on both `add` and `del`, that specific label will exist in the
// endpoint's labels.
func (d *Daemon) UpdateSecLabels(id string, add, del labels.Labels) middleware.Responder {
	d.conf.ValidLabelPrefixesMU.RLock()
	addLabels := d.conf.ValidLabelPrefixes.FilterLabels(add)
	delLabels := d.conf.ValidLabelPrefixes.FilterLabels(del)
	d.conf.ValidLabelPrefixesMU.RUnlock()

	if len(addLabels) == 0 && len(delLabels) == 0 {
		return nil
	}

	ep, err := endpointmanager.Lookup(id)
	if err != nil {
		return apierror.Error(GetEndpointIDInvalidCode, err)
	}
	if ep == nil {
		return NewPutEndpointIDLabelsNotFound()
	}

	ep.Mutex.RLock()
	epDockerID := ep.DockerID
	oldLabels := ep.OpLabels.DeepCopy()
	ep.Mutex.RUnlock()

	d.containersMU.RLock()
	cont := d.containers[epDockerID]
	d.containersMU.RUnlock()

	contID := ""
	if cont != nil {
		contID = cont.ID
	}

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

	if len(addLabels) > 0 {
		for k, v := range addLabels {
			if oldLabels.Disabled[k] != nil {
				delete(oldLabels.Disabled, k)
				oldLabels.Orchestration[k] = v
			} else if oldLabels.Orchestration[k] == nil {
				oldLabels.Custom[k] = v
			}
		}
	}

	identity, newHash, err2 := d.updateEndpointIdentity(ep.StringID(), ep.LabelsHash, oldLabels)
	if err2 != nil {
		return apierror.Error(PutEndpointIDLabelsUpdateFailedCode, err2)
	}
	ep.Mutex.Lock()
	ep.LabelsHash = newHash
	ep.OpLabels = *oldLabels
	ep.Mutex.Unlock()

	// FIXME: Undo identity update?

	ep, _ = endpointmanager.Lookup(id)
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
		log.Debugf("NewPutEndpointIDLabelsNotFound container %s for endpoint %s not found", id, ep.StringID())
	}

	d.SetEndpointIdentity(ep, contID, "", identity)

	// FIXME if the labels weren't changed do we still need to regenerate?
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
