// Copyright 2016-2018 Authors of Cilium
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
	"bytes"
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/apierror"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	ipCacheBPF "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/lxcmap"

	"github.com/go-openapi/runtime/middleware"
	"github.com/sirupsen/logrus"
)

type getEndpoint struct {
	d *Daemon
}

func NewGetEndpointHandler(d *Daemon) GetEndpointHandler {
	return &getEndpoint{d: d}
}

func (h *getEndpoint) Handle(params GetEndpointParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /endpoint request")
	resEPs := getEndpointList(params)

	if params.Labels != nil && len(resEPs) == 0 {
		return NewGetEndpointNotFound()
	}

	return NewGetEndpointOK().WithPayload(resEPs)
}

func getEndpointList(params GetEndpointParams) []*models.Endpoint {
	var (
		epModelsWg, epsAppendWg sync.WaitGroup
		convertedLabels         labels.Labels
		resEPs                  []*models.Endpoint
	)

	if params.Labels != nil {
		// Convert params.Labels to model that we can compare with the endpoint's labels.
		convertedLabels = labels.NewLabelsFromModel(params.Labels)
	}

	eps := endpointmanager.GetEndpoints()
	epModelsCh := make(chan *models.Endpoint, len(eps))

	epModelsWg.Add(len(eps))
	for _, ep := range eps {
		go func(wg *sync.WaitGroup, epChan chan<- *models.Endpoint, ep *endpoint.Endpoint) {
			if ep.HasLabels(convertedLabels) {
				epChan <- ep.GetModel()
			}
			wg.Done()
		}(&epModelsWg, epModelsCh, ep)
	}

	epsAppendWg.Add(1)
	// This needs to be done over channels since we might not receive all
	// the existing endpoints since not all endpoints contain the list of
	// labels that we will use to filter in `ep.HasLabels(convertedLabels)`
	go func(epsAppended *sync.WaitGroup) {
		for ep := range epModelsCh {
			resEPs = append(resEPs, ep)
		}
		epsAppended.Done()
	}(&epsAppendWg)

	epModelsWg.Wait()
	close(epModelsCh)
	epsAppendWg.Wait()

	return resEPs
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

// createEndpoint attempts to create the endpoint corresponding to the change
// request that was specified. Returns an HTTP code response code and an
// error msg (or nil on success).
func (d *Daemon) createEndpoint(epTemplate *models.EndpointChangeRequest, id string, lbls []string) (int, error) {
	addLabels := labels.ParseStringLabels(lbls)
	ep, err := endpoint.NewEndpointFromChangeModel(epTemplate, addLabels)
	if err != nil {
		return PutEndpointIDInvalidCode, err
	}
	ep.SetDefaultOpts(d.conf.Opts)

	oldEp, err2 := endpointmanager.Lookup(id)
	if err2 != nil {
		return PutEndpointIDInvalidCode, err2
	} else if oldEp != nil {
		return PutEndpointIDExistsCode, fmt.Errorf("Endpoint ID %s exists", id)
	}
	if err = endpoint.APICanModify(ep); err != nil {
		return PutEndpointIDInvalidCode, err
	}

	if err := endpointmanager.AddEndpoint(d, ep, "Create endpoint from API PUT"); err != nil {
		log.WithError(err).Warn("Aborting endpoint join")
		return PutEndpointIDFailedCode, err
	}

	add := labels.NewLabelsFromModel(lbls)

	if len(add) > 0 {
		code, errLabelsAdd := d.updateEndpointLabels(id, add, labels.Labels{})
		if errLabelsAdd != nil {
			// XXX: Why should the endpoint remain in this case?
			log.WithFields(logrus.Fields{
				logfields.EndpointID:              id,
				logfields.IdentityLabels:          logfields.Repr(add),
				logfields.IdentityLabels + ".bad": errLabelsAdd,
			}).Error("Could not add labels while creating an ep due to bad labels")
			return code, errLabelsAdd
		}
	}

	return PutEndpointIDCreatedCode, nil
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

	code, err := h.d.createEndpoint(epTemplate, params.ID, params.Endpoint.Labels)
	if err != nil {
		apierror.Error(code, err)
	}
	return NewPutEndpointIDCreated()
}

type patchEndpointID struct {
	d *Daemon
}

func NewPatchEndpointIDHandler(d *Daemon) PatchEndpointIDHandler {
	return &patchEndpointID{d: d}
}

func validPatchTransitionState(state models.EndpointState) bool {
	switch string(state) {
	case "", endpoint.StateWaitingForIdentity, endpoint.StateReady:
		return true
	}
	return false
}

func (h *patchEndpointID) Handle(params PatchEndpointIDParams) middleware.Responder {
	scopedLog := log.WithField(logfields.Params, logfields.Repr(params))
	scopedLog.Debug("PATCH /endpoint/{id} request")

	epTemplate := params.Endpoint

	// Validate the template. Assignment afterwards is atomic.
	// Note: newEp's labels are ignored.
	addLabels := labels.ParseStringLabels(params.Endpoint.Labels)
	newEp, err2 := endpoint.NewEndpointFromChangeModel(epTemplate, addLabels)
	if err2 != nil {
		return apierror.Error(PutEndpointIDInvalidCode, err2)
	}

	// Log invalid state transitions, but do not error out for backwards
	// compatibility.
	if !validPatchTransitionState(epTemplate.State) {
		scopedLog.Debugf("PATCH /endpoint/{id} to invalid state '%s'", epTemplate.State)
	}

	ep, err := endpointmanager.Lookup(params.ID)
	if err != nil {
		return apierror.Error(GetEndpointIDInvalidCode, err)
	}
	if ep == nil {
		return NewPatchEndpointIDNotFound()
	}
	if err = endpoint.APICanModify(ep); err != nil {
		return apierror.Error(PatchEndpointIDInvalidCode, err)
	}

	// FIXME: Support changing these?
	//  - container ID
	//  - docker network id
	//  - docker endpoint id
	//
	//  Support arbitrary changes? Support only if unset?

	ep.Mutex.Lock()

	// The endpoint may have just been deleted since the lookup, so return
	// that it can't be found.
	if ep.GetStateLocked() == endpoint.StateDisconnecting ||
		ep.GetStateLocked() == endpoint.StateDisconnected {
		ep.Mutex.Unlock()
		return NewPatchEndpointIDNotFound()
	}

	changed := false

	if epTemplate.InterfaceIndex != 0 && ep.IfIndex != newEp.IfIndex {
		ep.IfIndex = newEp.IfIndex
		changed = true
	}

	if epTemplate.InterfaceName != "" && ep.IfName != newEp.IfName {
		ep.IfName = newEp.IfName
		changed = true
	}

	// Only support transition to waiting-for-identity state, also
	// if the request is for ready state, as we will check the
	// existence of the security label below. Other transitions
	// are always internally managed, but we do not error out for
	// backwards compatibility.
	if epTemplate.State != "" &&
		validPatchTransitionState(epTemplate.State) &&
		ep.GetStateLocked() != endpoint.StateWaitingForIdentity {
		// Will not change state if the current state does not allow the transition.
		if ep.SetStateLocked(endpoint.StateWaitingForIdentity, "Update endpoint from API PATCH") {
			changed = true
		}
	}

	if epTemplate.Mac != "" && bytes.Compare(ep.LXCMAC, newEp.LXCMAC) != 0 {
		ep.LXCMAC = newEp.LXCMAC
		changed = true
	}

	if epTemplate.HostMac != "" && bytes.Compare(ep.NodeMAC, newEp.NodeMAC) != 0 {
		ep.NodeMAC = newEp.NodeMAC
		changed = true
	}

	if epTemplate.Addressing != nil {
		if ip := epTemplate.Addressing.IPV6; ip != "" && bytes.Compare(ep.IPv6, newEp.IPv6) != 0 {
			ep.IPv6 = newEp.IPv6
			changed = true
		}

		if ip := epTemplate.Addressing.IPV4; ip != "" && bytes.Compare(ep.IPv4, newEp.IPv4) != 0 {
			ep.IPv4 = newEp.IPv4
			changed = true
		}
	}

	// If desired state is waiting-for-identity but identity is already
	// known, bump it to ready state immediately to force re-generation
	if ep.GetStateLocked() == endpoint.StateWaitingForIdentity && ep.SecurityIdentity != nil {
		ep.SetStateLocked(endpoint.StateReady, "Preparing to force endpoint regeneration because identity is known while handling API PATCH")
		changed = true
	}

	wait := false
	if changed {
		// Force policy regeneration as endpoint's configuration was changed.
		// Other endpoints need not be regenerated as no labels were changed.
		ep.ForcePolicyCompute()
		// Transition to waiting-to-regenerate if ready.
		if ep.GetStateLocked() == endpoint.StateReady {
			ep.SetStateLocked(endpoint.StateWaitingToRegenerate, "Forcing endpoint regeneration because identity is known while handling API PATCH")
		}
		if ep.GetStateLocked() == endpoint.StateWaitingToRegenerate {
			wait = true
		}
	}
	ep.Mutex.Unlock()

	if wait {
		if err := ep.RegenerateWait(h.d, "Waiting on endpoint regeneration because identity is known while handling API PATCH"); err != nil {
			return apierror.Error(PatchEndpointIDFailedCode, err)
		}
		// FIXME: Special return code to indicate regeneration happened?
	}

	return NewPatchEndpointIDOK()
}

func (d *Daemon) deleteEndpoint(ep *endpoint.Endpoint) int {
	scopedLog := log.WithField(logfields.EndpointID, ep.ID)
	errors := d.deleteEndpointQuiet(ep)
	for _, err := range errors {
		scopedLog.WithError(err).Warn("Ignoring error while deleting endpoint")
	}
	return len(errors)
}

func (d *Daemon) deleteEndpointQuiet(ep *endpoint.Endpoint) []error {
	errors := []error{}

	// Wait for existing builds to complete and prevent further builds
	ep.BuildMutex.Lock()

	// Lock out any other writers to the endpoint
	ep.Mutex.Lock()

	// In case multiple delete requests have been enqueued, have all of them
	// except the first return here.
	if ep.GetStateLocked() == endpoint.StateDisconnecting {
		ep.Mutex.Unlock()
		ep.BuildMutex.Unlock()
		return []error{}
	}
	ep.SetStateLocked(endpoint.StateDisconnecting, "Deleting endpoint")

	// Remove the endpoint before we clean up. This ensures it is no longer
	// listed or queued for rebuilds.
	endpointmanager.Remove(ep)

	// If dry mode is enabled, no changes to BPF maps are performed
	if !d.DryModeEnabled() {
		errors := lxcmap.DeleteElement(ep)

		if ep.Consumable != nil {
			ep.Consumable.RemovePolicyMap(ep.PolicyMap)
		}

		// Remove policy BPF map
		if err := os.RemoveAll(ep.PolicyMapPathLocked()); err != nil {
			errors = append(errors, fmt.Errorf("unable to remove policy map file %s: %s", ep.PolicyMapPathLocked(), err))
		}

		// Remove calls BPF map
		if err := os.RemoveAll(ep.CallsMapPathLocked()); err != nil {
			errors = append(errors, fmt.Errorf("unable to remove calls map file %s: %s", ep.CallsMapPathLocked(), err))
		}

		// Remove IPv6 connection tracking map
		if err := os.RemoveAll(ep.Ct6MapPathLocked()); err != nil {
			errors = append(errors, fmt.Errorf("unable to remove IPv6 CT map %s: %s", ep.Ct6MapPathLocked(), err))
		}

		// Remove IPv4 connection tracking map
		if err := os.RemoveAll(ep.Ct4MapPathLocked()); err != nil {
			errors = append(errors, fmt.Errorf("unable to remove IPv4 CT map %s: %s", ep.Ct4MapPathLocked(), err))
		}

		// Remove handle_policy() tail call entry for EP
		if err := ep.RemoveFromGlobalPolicyMap(); err != nil {
			errors = append(errors, fmt.Errorf("unable to remove endpoint from global policy map: %s", err))
		}
	}

	if !d.conf.IPv4Disabled {
		if err := ipam.ReleaseIP(ep.IPv4.IP()); err != nil {
			errors = append(errors, fmt.Errorf("unable to release ipv4 address: %s", err))
		}
	}

	if err := ipam.ReleaseIP(ep.IPv6.IP()); err != nil {
		errors = append(errors, fmt.Errorf("unable to release ipv6 address: %s", err))
	}

	completionCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	ep.ProxyWaitGroup = completion.NewWaitGroup(completionCtx)

	errors = append(errors, ep.LeaveLocked(d)...)
	ep.Mutex.Unlock()

	err := ep.WaitForProxyCompletions()
	if err != nil {
		errors = append(errors, fmt.Errorf("unable to remove proxy redirects: %s", err))
	}
	cancel()
	ep.ProxyWaitGroup = nil

	ep.BuildMutex.Unlock()

	return errors
}

func (d *Daemon) DeleteEndpoint(id string) (int, error) {
	if ep, err := endpointmanager.Lookup(id); err != nil {
		return 0, apierror.Error(DeleteEndpointIDInvalidCode, err)
	} else if ep == nil {
		return 0, apierror.New(DeleteEndpointIDNotFoundCode, "endpoint not found")
	} else if err = endpoint.APICanModify(ep); err != nil {
		return 0, apierror.Error(DeleteEndpointIDInvalidCode, err)
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

// EndpointUpdate updates the options of the given endpoint and regenerates the endpoint
func (d *Daemon) EndpointUpdate(id string, opts models.ConfigurationMap) error {
	ep, err := endpointmanager.Lookup(id)
	if err != nil {
		return apierror.Error(PatchEndpointIDInvalidCode, err)
	}
	if err = endpoint.APICanModify(ep); err != nil {
		return apierror.Error(PatchEndpointIDInvalidCode, err)
	}

	if ep != nil {
		if err := ep.Update(d, opts); err != nil {
			switch err.(type) {
			case endpoint.UpdateValidationError:
				return apierror.Error(PatchEndpointIDConfigInvalidCode, err)
			default:
				return apierror.Error(PatchEndpointIDConfigFailedCode, err)
			}
		}
		ep.Mutex.RLock()
		endpointmanager.UpdateReferences(ep)
		ep.Mutex.RUnlock()
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

type getEndpointIDLog struct {
	d *Daemon
}

func NewGetEndpointIDLogHandler(d *Daemon) GetEndpointIDLogHandler {
	return &getEndpointIDLog{d: d}
}

func (h *getEndpointIDLog) Handle(params GetEndpointIDLogParams) middleware.Responder {
	log.WithField(logfields.EndpointID, params.ID).Debug("GET /endpoint/{id}/log request")

	ep, err := endpointmanager.Lookup(params.ID)

	if err != nil {
		return apierror.Error(GetEndpointIDLogInvalidCode, err)
	} else if ep == nil {
		return NewGetEndpointIDLogNotFound()
	} else {
		return NewGetEndpointIDLogOK().WithPayload(ep.Status.GetModel())
	}
}

type getEndpointIDHealthz struct {
	d *Daemon
}

func NewGetEndpointIDHealthzHandler(d *Daemon) GetEndpointIDHealthzHandler {
	return &getEndpointIDHealthz{d: d}
}

func (h *getEndpointIDHealthz) Handle(params GetEndpointIDHealthzParams) middleware.Responder {
	log.WithField(logfields.EndpointID, params.ID).Debug("GET /endpoint/{id}/log request")

	ep, err := endpointmanager.Lookup(params.ID)

	if err != nil {
		return apierror.Error(GetEndpointIDHealthzInvalidCode, err)
	} else if ep == nil {
		return NewGetEndpointIDHealthzNotFound()
	} else {
		return NewGetEndpointIDHealthzOK().WithPayload(ep.GetHealthModel())
	}
}

func checkLabels(add, del labels.Labels) (addLabels, delLabels labels.Labels, ok bool) {
	addLabels, _ = labels.FilterLabels(add)
	delLabels, _ = labels.FilterLabels(del)

	if len(addLabels) == 0 && len(delLabels) == 0 {
		return nil, nil, false
	}
	return addLabels, delLabels, true
}

// updateEndpointLabels add and deletes the given labels on given endpoint ID.
// The received `add` and `del` labels will be filtered with the valid label
// prefixes.
// The `add` labels take precedence over `del` labels, this means if the same
// label is set on both `add` and `del`, that specific label will exist in the
// endpoint's labels.
// Returns an HTTP response code and an error msg (or nil on success).
func (d *Daemon) updateEndpointLabels(id string, add, del labels.Labels) (int, error) {
	addLabels, delLabels, ok := checkLabels(add, del)
	if !ok {
		return 0, nil
	}

	ep, err := endpointmanager.Lookup(id)
	if err != nil {
		return GetEndpointIDInvalidCode, err
	}
	if ep == nil {
		return PutEndpointIDLabelsNotFoundCode, fmt.Errorf("Endpoint ID %s not found", id)
	}

	if err := ep.ModifyIdentityLabels(d, addLabels, delLabels); err != nil {
		return PutEndpointIDLabelsNotFoundCode, err
	}

	return PutEndpointIDLabelsOKCode, nil
}

// updateEndpointLabelsFromAPI is the same as updateEndpointLabels(), but also
// performs checks for whether the endpoint may be modified by an API call.
func (d *Daemon) updateEndpointLabelsFromAPI(id string, add, del labels.Labels) (int, error) {
	addLabels, delLabels, ok := checkLabels(add, del)
	if !ok {
		return 0, nil
	}
	if lbls := addLabels.FindReserved(); lbls != nil {
		return PutEndpointIDLabelsUpdateFailedCode, fmt.Errorf("Not allowed to add reserved labels: %s", lbls)
	} else if lbls := delLabels.FindReserved(); lbls != nil {
		return PutEndpointIDLabelsUpdateFailedCode, fmt.Errorf("Not allowed to delete reserved labels: %s", lbls)
	}

	ep, err := endpointmanager.Lookup(id)
	if err != nil {
		return GetEndpointIDInvalidCode, err
	}
	if ep == nil {
		return PutEndpointIDLabelsNotFoundCode, fmt.Errorf("Endpoint ID %s not found", id)
	}
	if err = endpoint.APICanModify(ep); err != nil {
		return PutEndpointIDInvalidCode, err
	}

	if err := ep.ModifyIdentityLabels(d, addLabels, delLabels); err != nil {
		return PutEndpointIDLabelsNotFoundCode, err
	}

	return PutEndpointIDLabelsOKCode, nil
}

type putEndpointIDLabels struct {
	daemon *Daemon
}

func NewPutEndpointIDLabelsHandler(d *Daemon) PutEndpointIDLabelsHandler {
	return &putEndpointIDLabels{daemon: d}
}

func (h *putEndpointIDLabels) Handle(params PutEndpointIDLabelsParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("PUT /endpoint/{id}/labels request")

	d := h.daemon
	mod := params.Configuration
	add := labels.NewLabelsFromModel(mod.Add)
	del := labels.NewLabelsFromModel(mod.Delete)

	code, err := d.updateEndpointLabelsFromAPI(params.ID, add, del)
	if err != nil {
		return apierror.Error(code, err)
	}
	return NewPutEndpointIDLabelsOK()
}

// OnIPIdentityCacheChange is called whenever there is a change of state in the
// IPCache (pkg/ipcache).
// TODO (FIXME): GH-3161.
func (d *Daemon) OnIPIdentityCacheChange(modType ipcache.CacheModification, ipIDPair identity.IPIdentityPair) {

	log.WithFields(logrus.Fields{logfields.Modification: modType,
		logfields.IPAddr:   ipIDPair.IP,
		logfields.Identity: ipIDPair.ID}).
		Debug("daemon notified of IP-Identity cache state change")

	// TODO - see if we can factor this into an interface under something like
	// pkg/datapath instead of in the daemon directly so that the code is more
	// logically located.

	// Update BPF Maps.
	key := ipCacheBPF.NewEndpointKey(ipIDPair.IP)

	switch modType {
	case ipcache.Upsert:
		value := ipCacheBPF.RemoteEndpointInfo{SecurityIdentity: uint16(ipIDPair.ID)}
		err := ipCacheBPF.IPCache.Update(key, value)
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{"key": key.String(),
				"value": value.String()}).
				Warning("unable to update bpf map")
		}
	case ipcache.Delete:
		err := ipCacheBPF.IPCache.Delete(key)
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{"key": key.String()}).
				Warning("unable to delete from bpf map")
		}
	default:
		log.WithField("modificationType", modType).Warning("cache modification type not supported")
	}
}

// OnIPIdentityCacheGC spawns a controller which synchronizes the BPF IPCache Map
// with the in-memory IP-Identity cache.
func (d *Daemon) OnIPIdentityCacheGC() {

	// This controller ensures that the in-memory IP-identity cache is in-sync
	// with the BPF map on disk. These can get out of sync if the cilium-agent
	// is offline for some time, as the maps persist on the BPF filesystem.
	// In the case that there is some loss of event history in the key-value
	// store (e.g., compaction in etcd), we cannot rely upon the key-value store
	// fully to give us the history of all events. As such, periodically check
	// for inconsistencies in the data-path with that in the agent to ensure
	// consistent state.
	controller.NewManager().UpdateController("ipcache-bpf-garbage-collection",
		controller.ControllerParams{
			DoFunc: func() error {

				// Since controllers run asynchronously, need to make sure
				// IPIdentityCache is not being updated concurrently while we do
				// GC;
				ipcache.IPIdentityCache.RLock()
				defer ipcache.IPIdentityCache.RUnlock()

				keysToRemove := map[ipCacheBPF.EndpointKey]struct{}{}

				// Add all keys which are in BPF map but not in in-memory cache
				// to set of keys to remove from BPF map.
				cb := func(key bpf.MapKey, value bpf.MapValue) {
					k := key.(ipCacheBPF.EndpointKey)
					keyToIP := k.String()

					// Don't RLock as part of the same goroutine.
					if _, exists := ipcache.IPIdentityCache.LookupByIPRLocked(keyToIP); !exists {
						// Cannot delete from map during callback because DumpWithCallback
						// RLocks the map.
						keysToRemove[k] = struct{}{}
					}
				}

				if err := ipCacheBPF.IPCache.DumpWithCallback(cb); err != nil {
					return fmt.Errorf("error dumping ipcache BPF map: %s", err)
				}

				// Remove all keys which are not in in-memory cache from BPF map
				// for consistency.
				for k := range keysToRemove {
					log.WithFields(logrus.Fields{logfields.BPFMapKey: k}).
						Debug("deleting from ipcache BPF map")
					if err := ipCacheBPF.IPCache.Delete(k); err != nil {
						return fmt.Errorf("error deleting key %s from ipcache BPF map: %s", k, err)
					}
				}
				return nil
			},
			RunInterval: time.Duration(5) * time.Minute,
		})
}
