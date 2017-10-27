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
	"fmt"
	"os"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/apierror"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logfields"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/policy"

	"github.com/go-openapi/runtime/middleware"
	log "github.com/sirupsen/logrus"
)

type getEndpoint struct {
	d *Daemon
}

func NewGetEndpointHandler(d *Daemon) GetEndpointHandler {
	return &getEndpoint{d: d}
}

func (h *getEndpoint) Handle(params GetEndpointParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /endpoint request")

	modelChan := make(chan *models.Endpoint, 1)
	defer close(modelChan)

	// FIXME @aanm hide use of endpoint manager lock
	endpointmanager.Mutex.RLock()
	numEndpoints := len(endpointmanager.Endpoints)
	eps := make([]*models.Endpoint, 0, numEndpoints)

	if params.Labels == nil {
		for _, v := range endpointmanager.Endpoints {
			go func(ep *endpoint.Endpoint) {
				modelChan <- ep.GetModel()
			}(v)
		}
		endpointmanager.Mutex.RUnlock()
		for i := 0; i < numEndpoints; i++ {
			eps = append(eps, <-modelChan)
		}
		return NewGetEndpointOK().WithPayload(eps)
	}

	// Convert params.Labels to model that we can compare with the endpoint's labels.
	convertedLabels := labels.NewLabelsFromModel(params.Labels)

	for _, v := range endpointmanager.Endpoints {
		go func(ep *endpoint.Endpoint) {
			ep.Mutex.RLock()
			if ep.HasLabels(convertedLabels) {
				modelChan <- ep.GetModelRLocked()
			}
			ep.Mutex.RUnlock()
		}(v)
	}
	endpointmanager.Mutex.RUnlock()

	for i := 0; i < numEndpoints; i++ {
		eps = append(eps, <-modelChan)
	}

	if len(eps) == 0 {
		return NewGetEndpointNotFound()
	}

	return NewGetEndpointOK().WithPayload(eps)
}

type getEndpointID struct {
	d *Daemon
}

func NewGetEndpointIDHandler(d *Daemon) GetEndpointIDHandler {
	return &getEndpointID{d: d}
}

func (h *getEndpointID) Handle(params GetEndpointIDParams) middleware.Responder {
	log.WithField(logfields.EndpointID, params.ID).Debug("GET /endpoint/{id} request")

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
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("PUT /endpoint/{id} request")

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
	alwaysEnforce := policy.GetPolicyEnabled() == endpoint.AlwaysEnforce
	ep.Opts.Set(endpoint.OptionPolicy, alwaysEnforce)

	endpointmanager.Mutex.Lock()
	defer endpointmanager.Mutex.Unlock()

	oldEp, err2 := endpointmanager.LookupLocked(params.ID)
	if err2 != nil {
		return apierror.Error(GetEndpointIDInvalidCode, err2)
	} else if oldEp != nil {
		return NewPutEndpointIDExists()
	}

	if err := ep.CreateDirectory(); err != nil {
		log.WithError(err).Warn("Aborting endpoint join")
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
			log.WithFields(log.Fields{
				logfields.EndpointID:              params.ID,
				logfields.IdentityLabels:          logfields.Repr(add),
				logfields.IdentityLabels + ".bad": errLabelsAdd,
			}).Error("Could not add labels while creating an ep due to bad labels")
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
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("PATCH /endpoint/{id} request")

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

func (d *Daemon) deleteEndpoint(ep *endpoint.Endpoint) int {
	scopedLog := log.WithField(logfields.EndpointID, ep.ID)

	// Wait for existing builds to complete and prevent further builds
	ep.BuildMutex.Lock()
	defer ep.BuildMutex.Unlock()

	// Lock out any other writers to the endpoint
	ep.Mutex.Lock()

	// In case multiple delete requests have been enqueued, have all of them
	// except the first return here.
	if ep.IsDisconnectingLocked() {
		ep.Mutex.Unlock()
		return 0
	}

	ep.State = endpoint.StateDisconnecting

	sha256sum := ep.OpLabels.IdentityLabels().SHA256Sum()
	if err := d.DeleteIdentityBySHA256(sha256sum, ep.StringID()); err != nil {
		log.WithError(err).WithFields(log.Fields{
			logfields.SHA:            sha256sum,
			logfields.IdentityLabels: ep.OpLabels.IdentityLabels(),
		}).Error("Error while deleting labels")
	}

	var errors int

	// If dry mode is enabled, no changes to BPF maps are performed
	if !d.DryModeEnabled() {
		errors := lxcmap.DeleteElement(ep)

		if ep.Consumable != nil {
			ep.Consumable.RemoveMap(ep.PolicyMap)
		}

		// Remove policy BPF map
		if err := os.RemoveAll(ep.PolicyMapPathLocked()); err != nil {
			scopedLog.WithError(err).WithField(logfields.Path, ep.PolicyMapPathLocked()).Warn("Unable to remove policy map file")
			errors++
		}

		// Remove calls BPF map
		if err := os.RemoveAll(ep.CallsMapPathLocked()); err != nil {
			scopedLog.WithError(err).WithField(logfields.Path, ep.CallsMapPathLocked()).Warn("Unable to remove calls map file")
			errors++
		}

		// Remove IPv6 connection tracking map
		if err := os.RemoveAll(ep.Ct6MapPathLocked()); err != nil {
			scopedLog.WithError(err).WithField(logfields.Path, ep.Ct6MapPathLocked()).Warn("Unable to remove IPv6 CT map file")
			errors++
		}

		// Remove IPv4 connection tracking map
		if err := os.RemoveAll(ep.Ct4MapPathLocked()); err != nil {
			scopedLog.WithError(err).WithField(logfields.Path, ep.Ct4MapPathLocked()).Warn("Unable to remove IPv4 CT map file")
			errors++
		}

		// Remove handle_policy() tail call entry for EP
		if err := ep.RemoveFromGlobalPolicyMap(); err != nil {
			scopedLog.WithError(err).Warn("Unable to remove EP from global policy map!")
			errors++
		}
	}

	if !d.conf.IPv4Disabled {
		if err := ipam.ReleaseIP(ep.IPv4.IP()); err != nil {
			scopedLog.WithError(err).WithField(logfields.IPAddr, ep.IPv4.IP()).Warn("Error while releasing IPv4")
			errors++
		}
	}

	if err := ipam.ReleaseIP(ep.IPv6.IP()); err != nil {
		scopedLog.WithError(err).WithField(logfields.IPAddr, ep.IPv6.IP()).Warn("Error while releasing IPv6")
		errors++
	}

	ep.LeaveLocked(d)
	ep.Mutex.Unlock()

	endpointmanager.Remove(ep)

	return errors
}

func (d *Daemon) DeleteEndpoint(id string) (int, error) {
	if ep, err := endpointmanager.Lookup(id); err != nil {
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
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("DELETE /endpoint/{id} request")

	d := h.daemon
	if nerr, err := d.DeleteEndpoint(params.ID); err != nil {
		if apierr, ok := err.(*apierror.APIError); ok {
			return apierr
		}
		return apierror.Error(DeleteEndpointIDErrorsCode, err)
	} else if nerr > 0 {
		return NewDeleteEndpointIDErrors().WithPayload(int64(nerr))
	} else {
		return NewDeleteEndpointIDOK()
	}
}

// EndpointUpdate updates the given endpoint and regenerates the endpoint
func (d *Daemon) EndpointUpdate(id string, opts models.ConfigurationMap) error {
	ep, err := endpointmanager.Lookup(id)
	if err != nil {
		return apierror.Error(PatchEndpointIDInvalidCode, err)
	}

	if ep != nil {
		invalidateCache()
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
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("PATCH /endpoint/{id}/config request")

	d := h.daemon
	if err := d.EndpointUpdate(params.ID, params.Configuration); err != nil {
		if apierr, ok := err.(*apierror.APIError); ok {
			return apierr
		}
		return apierror.Error(PatchEndpointIDFailedCode, err)
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
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /endpoint/{id}/config")

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
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /endpoint/{id}/labels")

	ep, err := endpointmanager.Lookup(params.ID)
	if err != nil {
		return apierror.Error(GetEndpointIDInvalidCode, err)
	}
	if ep == nil {
		return NewGetEndpointIDLabelsNotFound()
	}

	ep.Mutex.RLock()
	cfg := models.LabelConfiguration{
		Disabled:              ep.OpLabels.Disabled.GetModel(),
		Custom:                ep.OpLabels.Custom.GetModel(),
		OrchestrationIdentity: ep.OpLabels.OrchestrationIdentity.GetModel(),
		OrchestrationInfo:     ep.OpLabels.OrchestrationInfo.GetModel(),
	}
	ep.Mutex.RUnlock()

	return NewGetEndpointIDLabelsOK().WithPayload(&cfg)
}

// UpdateSecLabels add and deletes the given labels on given endpoint ID.
// The received `add` and `del` labels will be filtered with the valid label
// prefixes.
// The `add` labels take precedence over `del` labels, this means if the same
// label is set on both `add` and `del`, that specific label will exist in the
// endpoint's labels.
func (d *Daemon) UpdateSecLabels(id string, add, del labels.Labels) middleware.Responder {
	addLabels, _ := labels.FilterLabels(add)
	delLabels, _ := labels.FilterLabels(del)

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
	oldLabels := ep.OpLabels.DeepCopy()
	ep.Mutex.RUnlock()

	if len(delLabels) > 0 {
		for k := range delLabels {
			// The change request is accepted if the label is on
			// any of the lists. If the label is already disabled,
			// we will simply ignore that change.
			if oldLabels.OrchestrationIdentity[k] != nil ||
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
			if oldLabels.OrchestrationIdentity[k] != nil {
				delete(oldLabels.OrchestrationIdentity, k)
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
				oldLabels.OrchestrationIdentity[k] = v
			} else if oldLabels.OrchestrationIdentity[k] == nil {
				oldLabels.Custom[k] = v
			}
		}
	}

	identity, newHash, err2 := d.updateEndpointIdentity(ep.StringID(), ep.LabelsHash, oldLabels)
	if err2 != nil {
		return apierror.Error(PutEndpointIDLabelsUpdateFailedCode, err2)
	}

	ep.Mutex.Lock()
	if ep.State == endpoint.StateDisconnected {
		ep.Mutex.Unlock()
		if err := d.DeleteIdentity(identity.ID, ep.StringID()); err != nil {
			log.WithFields(log.Fields{
				logfields.EndpointID: ep.StringID(),
				logfields.Identity:   identity.ID,
			}).WithError(err).Warn("Unable to release temporary identity")
		}
		return NewPutEndpointIDLabelsNotFound()
	}

	ep.LabelsHash = newHash
	ep.OpLabels = *oldLabels
	ep.SetIdentity(d, identity)
	ep.Mutex.Unlock()

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

	log.WithField(logfields.Params, logfields.Repr(params)).Debug("PUT /endpoint/{id}/labels request")

	mod := params.Configuration
	add := labels.NewLabelsFromModel(mod.Add)
	del := labels.NewLabelsFromModel(mod.Delete)

	err := d.UpdateSecLabels(params.ID, add, del)
	if err != nil {
		return err
	}

	return NewPutEndpointIDLabelsOK()
}

// EndpointLabelsUpdate is called periodically to sync the labels of an
// endpoint. Calls to this function do not necessarily mean that the labels
// actually changed. The container runtime layer will periodically synchronize
// labels
// The responsibility of this function is to:
//  - resolve the identity and update the endpoint
//  - trigger endpoint regeneration if required
//  - trigger policy regeneration if required
func (d *Daemon) EndpointLabelsUpdate(ep *endpoint.Endpoint, identityLabels, infoLabels labels.Labels) error {
	log.WithFields(log.Fields{
		logfields.ContainerID:    ep.GetShortContainerID(),
		logfields.EndpointID:     ep.StringID(),
		logfields.IdentityLabels: identityLabels.String(),
		"infoLabels":             infoLabels.String(),
	}).Debug("Updating labels of endpoint")

	ep.UpdateOrchInformationLabels(infoLabels)
	ep.UpdateOrchIdentityLabels(identityLabels)

	// It's mandatory to update the endpoint identity in the KVStore.  This
	// way we keep the RefCount refreshed and the SecurityLabelID will not
	// be considered unused.
	identity, newHash, err := d.updateEndpointIdentity(ep.StringID(), ep.LabelsHash, &ep.OpLabels)
	if err != nil {
		return fmt.Errorf("Unable to update identity of endpoint")
	}

	// Set identity labels and identity associating while holding endpoint
	// lock never have a disconnect between labels and identity.
	ep.Mutex.Lock()

	// Endpoint might have transitioned to disconnected state. If
	// disconnected, do not associate the identity with the endpoint and
	// release it again
	if ep.State == endpoint.StateDisconnected {
		ep.Mutex.Unlock()
		if err := d.DeleteIdentity(identity.ID, ep.StringID()); err != nil {
			log.WithFields(log.Fields{
				logfields.EndpointID: ep.StringID(),
				logfields.Identity:   identity.ID,
			}).WithError(err).Warn("Unable to release temporary identity")
		}

		return fmt.Errorf("Endpoint is disconnected, aborting label update handler")
	}

	ep.LabelsHash = newHash
	oldIdentity := ep.GetIdentity()
	ep.SetIdentity(d, identity)
	ep.Mutex.Unlock()

	// Skip building endpoint if identity is invalid or unchanged
	if identity.ID != oldIdentity {
		ep.Regenerate(d)

		// FIXME: Does this rebuild epID twice?
		d.TriggerPolicyUpdates([]policy.NumericIdentity{identity.ID})
	}

	return nil
}
