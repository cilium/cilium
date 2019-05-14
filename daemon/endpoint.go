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
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/workloads"

	"github.com/go-openapi/runtime/middleware"
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
		return api.Error(GetEndpointIDInvalidCode, err)
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

func fetchK8sLabels(ep *endpoint.Endpoint) (labels.Labels, labels.Labels, error) {
	lbls, err := k8s.GetPodLabels(ep.GetK8sNamespace(), ep.GetK8sPodName())
	if err != nil {
		return nil, nil, err
	}

	k8sLbls := labels.Map2Labels(lbls, labels.LabelSourceK8s)
	identityLabels, infoLabels := labels.FilterLabels(k8sLbls)
	return identityLabels, infoLabels, nil
}

func invalidDataError(ep *endpoint.Endpoint, err error) (*endpoint.Endpoint, int, error) {
	ep.Logger(daemonSubsys).WithError(err).Warning("Creation of endpoint failed due to invalid data")
	return nil, PutEndpointIDInvalidCode, err
}

func (d *Daemon) errorDuringCreation(ep *endpoint.Endpoint, err error) (*endpoint.Endpoint, int, error) {
	d.deleteEndpointQuiet(ep, endpoint.DeleteConfig{
		// The IP has been provided by the caller and must be released
		// by the caller
		NoIPRelease: true,
	})
	ep.Logger(daemonSubsys).WithError(err).Warning("Creation of endpoint failed")
	return nil, PutEndpointIDFailedCode, err
}

// createEndpoint attempts to create the endpoint corresponding to the change
// request that was specified.
func (d *Daemon) createEndpoint(ctx context.Context, epTemplate *models.EndpointChangeRequest) (*endpoint.Endpoint, int, error) {
	ep, err := endpoint.NewEndpointFromChangeModel(d.policy, epTemplate)
	if err != nil {
		return invalidDataError(ep, fmt.Errorf("unable to parse endpoint parameters: %s", err))
	}

	oldEp := endpointmanager.LookupCiliumID(ep.ID)
	if oldEp != nil {
		return invalidDataError(ep, fmt.Errorf("endpoint ID %d already exists", ep.ID))
	}

	oldEp = endpointmanager.LookupContainerID(ep.ContainerID)
	if oldEp != nil {
		return invalidDataError(ep, fmt.Errorf("endpoint for container %s already exists", ep.ContainerID))
	}

	var checkIDs []string

	if ep.IPv4.IsSet() {
		checkIDs = append(checkIDs, endpointid.NewID(endpointid.IPv4Prefix, ep.IPv4.String()))
	}

	if ep.IPv6.IsSet() {
		checkIDs = append(checkIDs, endpointid.NewID(endpointid.IPv6Prefix, ep.IPv6.String()))
	}

	for _, id := range checkIDs {
		oldEp, err := endpointmanager.Lookup(id)
		if err != nil {
			return invalidDataError(ep, err)
		} else if oldEp != nil {
			return invalidDataError(ep, fmt.Errorf("IP %s is already in use", id))
		}
	}

	if err = endpoint.APICanModify(ep); err != nil {
		return invalidDataError(ep, err)
	}

	addLabels := labels.NewLabelsFromModel(epTemplate.Labels)
	infoLabels := labels.NewLabelsFromModel([]string{})

	if len(addLabels) > 0 {
		if lbls := addLabels.FindReserved(); lbls != nil {
			return invalidDataError(ep, fmt.Errorf("not allowed to add reserved labels: %s", lbls))
		}

		addLabels, _, _ = checkLabels(addLabels, nil)
		if len(addLabels) == 0 {
			return invalidDataError(ep, fmt.Errorf("no valid labels provided"))
		}
	}

	if ep.GetK8sNamespaceAndPodNameLocked() != "" && k8s.IsEnabled() {
		identityLabels, info, err := fetchK8sLabels(ep)
		if err != nil {
			ep.Logger("api").WithError(err).Warning("Unable to fetch kubernetes labels")
		} else {
			addLabels.MergeLabels(identityLabels)
			infoLabels.MergeLabels(info)
		}
	}

	if len(addLabels) == 0 {
		// If the endpoint has no labels, give the endpoint a special identity with
		// label reserved:init so we can generate a custom policy for it until we
		// get its actual identity.
		addLabels = labels.Labels{
			labels.IDNameInit: labels.NewLabel(labels.IDNameInit, "", labels.LabelSourceReserved),
		}
	}

	err = endpointmanager.AddEndpoint(d, ep, "Create endpoint from API PUT")
	logger := ep.Logger(daemonSubsys)
	if err != nil {
		return d.errorDuringCreation(ep, fmt.Errorf("unable to insert endpoint into manager: %s", err))
	}

	ep.UpdateLabels(ctx, d, addLabels, infoLabels, true)

	select {
	case <-ctx.Done():
		return d.errorDuringCreation(ep, fmt.Errorf("request cancelled while resolving identity"))
	default:
	}

	if err := ep.LockAlive(); err != nil {
		return d.errorDuringCreation(ep, fmt.Errorf("endpoint was deleted while processing the request"))
	}

	// Now that we have ep.ID we can pin the map from this point. This
	// also has to happen before the first build took place.
	if err = ep.PinDatapathMap(); err != nil {
		ep.Unlock()
		return d.errorDuringCreation(ep, fmt.Errorf("unable to pin datapath maps: %s", err))
	}

	build := ep.GetStateLocked() == endpoint.StateReady
	if build {
		ep.SetStateLocked(endpoint.StateWaitingToRegenerate, "Identity is known at endpoint creation time")
	}
	ep.Unlock()

	if build {
		// Do not synchronously regenerate the endpoint when first creating it.
		// We have custom logic later for waiting for specific checkpoints to be
		// reached upon regeneration later (checking for when BPF programs have
		// been compiled), as opposed to waiting for the entire regeneration to
		// be complete (including proxies being configured). This is done to
		// avoid a chicken-and-egg problem with L7 policies are imported which
		// select the endpoint being generated, as when such policies are
		// imported, regeneration blocks on waiting for proxies to be
		// configured. When Cilium is used with Istio, though, the proxy is
		// started as a sidecar, and is not launched yet when this specific code
		// is executed; if we waited for regeneration to be complete, including
		// proxy configuration, this code would effectively deadlock addition
		// of endpoints.
		ep.Regenerate(d, &endpoint.ExternalRegenerationMetadata{
			Reason:        "Initial build on endpoint creation",
			ParentContext: ctx,
		})
	}

	// Only used for CRI-O since it does not support events.
	if d.workloadsEventsCh != nil && ep.GetContainerID() != "" {
		d.workloadsEventsCh <- &workloads.EventMessage{
			WorkloadID: ep.GetContainerID(),
			EventType:  workloads.EventTypeStart,
		}
	}

	// Wait for endpoint to be in "ready" state if specified in API call.
	if !epTemplate.SyncBuildEndpoint {
		return ep, 0, nil
	}

	logger.Info("Waiting for endpoint to be generated")

	// Default timeout for PUT /endpoint/{id} is 60 seconds, so put timeout
	// in this function a bit below that timeout. If the timeout for clients
	// in API is below this value, they will get a message containing
	// "context deadline exceeded" if the operation takes longer than the
	// client's configured timeout value.
	ctx, cancel := context.WithTimeout(ctx, endpoint.EndpointGenerationTimeout)

	// Check the endpoint's state and labels periodically.
	ticker := time.NewTicker(1 * time.Second)
	defer func() {
		cancel()
		ticker.Stop()
	}()

	// Wait for any successful BPF regeneration, which is indicated by any
	// positive policy revision (>0). As long as at least one BPF
	// regeneration is successful, the endpoint has network connectivity
	// so we can return from the creation API call.
	revCh := ep.WaitForPolicyRevision(ctx, 1, nil)

	for {
		select {
		case <-revCh:
			if ctx.Err() == nil {
				// At least one BPF regeneration has successfully completed.
				return ep, 0, nil
			}

		case <-ctx.Done():
		case <-ticker.C:
			if err := ep.RLockAlive(); err != nil {
				return d.errorDuringCreation(ep, fmt.Errorf("endpoint was deleted while waiting for initial endpoint generation to complete"))
			}
			hasSidecarProxy := ep.HasSidecarProxy()
			ep.RUnlock()
			if hasSidecarProxy && ep.HasBPFProgram() {
				// If the endpoint is determined to have a sidecar proxy,
				// return immediately to let the sidecar container start,
				// in case it is required to enforce L7 rules.
				logger.Info("Endpoint has sidecar proxy, returning from synchronous creation request before regeneration has succeeded")
				return ep, 0, nil
			}
		}

		if ctx.Err() != nil {
			return d.errorDuringCreation(ep, fmt.Errorf("timeout while waiting for initial endpoint generation to complete"))
		}
	}
}

func (h *putEndpointID) Handle(params PutEndpointIDParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("PUT /endpoint/{id} request")
	epTemplate := params.Endpoint

	ep, code, err := h.d.createEndpoint(params.HTTPRequest.Context(), epTemplate)
	if err != nil {
		return api.Error(code, err)
	}

	ep.Logger(daemonSubsys).Info("Successful endpoint creation")

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
	newEp, err2 := endpoint.NewEndpointFromChangeModel(h.d.policy, epTemplate)
	if err2 != nil {
		return api.Error(PutEndpointIDInvalidCode, err2)
	}

	// Log invalid state transitions, but do not error out for backwards
	// compatibility.
	if !validPatchTransitionState(epTemplate.State) {
		scopedLog.Debugf("PATCH /endpoint/{id} to invalid state '%s'", epTemplate.State)
	}

	ep, err := endpointmanager.Lookup(params.ID)
	if err != nil {
		return api.Error(GetEndpointIDInvalidCode, err)
	}
	if ep == nil {
		return NewPatchEndpointIDNotFound()
	}
	if err = endpoint.APICanModify(ep); err != nil {
		return api.Error(PatchEndpointIDInvalidCode, err)
	}

	// FIXME: Support changing these?
	//  - container ID
	//  - docker network id
	//  - docker endpoint id
	//
	//  Support arbitrary changes? Support only if unset?

	if err := ep.LockAlive(); err != nil {
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

	if epTemplate.HostMac != "" && bytes.Compare(ep.GetNodeMAC(), newEp.NodeMAC) != 0 {
		ep.SetNodeMACLocked(newEp.NodeMAC)
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

	// TODO: Do something with the labels?
	// addLabels := labels.NewLabelsFromModel(params.Endpoint.Labels)

	// If desired state is waiting-for-identity but identity is already
	// known, bump it to ready state immediately to force re-generation
	if ep.GetStateLocked() == endpoint.StateWaitingForIdentity && ep.SecurityIdentity != nil {
		ep.SetStateLocked(endpoint.StateReady, "Preparing to force endpoint regeneration because identity is known while handling API PATCH")
		changed = true
	}

	reason := ""
	if changed {
		// Force policy regeneration as endpoint's configuration was changed.
		// Other endpoints need not be regenerated as no labels were changed.
		// Note that we still need to (eventually) regenerate the endpoint for
		// the changes to take effect.
		ep.ForcePolicyCompute()

		// Transition to waiting-to-regenerate if ready.
		if ep.GetStateLocked() == endpoint.StateReady {
			ep.SetStateLocked(endpoint.StateWaitingToRegenerate, "Forcing endpoint regeneration because identity is known while handling API PATCH")
		}

		switch ep.GetStateLocked() {
		case endpoint.StateWaitingToRegenerate:
			reason = "Waiting on endpoint regeneration because identity is known while handling API PATCH"
		case endpoint.StateWaitingForIdentity:
			reason = "Waiting on endpoint initial program regeneration while handling API PATCH"
		}
	}

	ep.UpdateLogger(nil)
	ep.Unlock()

	if reason != "" {
		if err := ep.RegenerateWait(h.d, reason); err != nil {
			return api.Error(PatchEndpointIDFailedCode, err)
		}
		// FIXME: Special return code to indicate regeneration happened?
	}

	return NewPatchEndpointIDOK()
}

func (d *Daemon) deleteEndpoint(ep *endpoint.Endpoint) int {
	scopedLog := log.WithField(logfields.EndpointID, ep.ID)
	errs := d.deleteEndpointQuiet(ep, endpoint.DeleteConfig{
		// If the IP is managed by an external IPAM, it does not need to be released
		NoIPRelease: ep.DatapathConfiguration.ExternalIPAM,
	})
	for _, err := range errs {
		scopedLog.WithError(err).Warn("Ignoring error while deleting endpoint")
	}
	return len(errs)
}

// deleteEndpointQuiet sets the endpoint into disconnecting state and removes
// it from Cilium, releasing all resources associated with it such as its
// visibility in the endpointmanager, its BPF programs and maps, (optional) IP,
// L7 policy configuration, directories and controllers.
//
// Specific users such as the cilium-health EP may choose not to release the IP
// when deleting the endpoint. Most users should pass true for releaseIP.
func (d *Daemon) deleteEndpointQuiet(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) []error {

	// Only used for CRI-O since it does not support events.
	if d.workloadsEventsCh != nil && ep.GetContainerID() != "" {
		d.workloadsEventsCh <- &workloads.EventMessage{
			WorkloadID: ep.GetContainerID(),
			EventType:  workloads.EventTypeDelete,
		}
	}

	errs := []error{}

	// Wait for existing builds to complete and prevent further builds
	ep.BuildMutex.Lock()

	// Given that we are deleting the endpoint and that no more builds are
	// going to occur for this endpoint, close the channel which signals whether
	// the endpoint has its BPF program compiled or not to avoid it persisting
	// if anything is blocking on it. If a delete request has already been
	// enqueued for this endpoint, this is a no-op.
	ep.CloseBPFProgramChannel()

	// Lock out any other writers to the endpoint
	ep.UnconditionalLock()

	// In case multiple delete requests have been enqueued, have all of
	// them except the first return here. Ignore the request if the
	// endpoint is already disconnected.
	switch ep.GetStateLocked() {
	case endpoint.StateDisconnecting, endpoint.StateDisconnected:
		ep.Unlock()
		ep.BuildMutex.Unlock()
		return []error{}
	}
	ep.SetStateLocked(endpoint.StateDisconnecting, "Deleting endpoint")

	// Since the endpoint is being deleted, we no longer need to run events
	// in its event queue.
	ep.EventQueue.Stop()

	// Remove the endpoint before we clean up. This ensures it is no longer
	// listed or queued for rebuilds.
	endpointmanager.Remove(ep)

	// If dry mode is enabled, no changes to BPF maps are performed
	if !option.Config.DryMode {
		if errs2 := lxcmap.DeleteElement(ep); errs2 != nil {
			errs = append(errs, errs2...)
		}

		if errs2 := ep.DeleteMapsLocked(); errs2 != nil {
			errs = append(errs, errs2...)
		}
	}

	if !conf.NoIPRelease {
		if option.Config.EnableIPv4 {
			if err := d.ipam.ReleaseIP(ep.IPv4.IP()); err != nil {
				errs = append(errs, fmt.Errorf("unable to release ipv4 address: %s", err))
			}
		}
		if option.Config.EnableIPv6 {
			if err := d.ipam.ReleaseIP(ep.IPv6.IP()); err != nil {
				errs = append(errs, fmt.Errorf("unable to release ipv6 address: %s", err))
			}
		}
	}

	completionCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	proxyWaitGroup := completion.NewWaitGroup(completionCtx)

	errs = append(errs, ep.LeaveLocked(d, proxyWaitGroup, conf)...)
	ep.Unlock()

	err := ep.WaitForProxyCompletions(proxyWaitGroup)
	if err != nil {
		errs = append(errs, fmt.Errorf("unable to remove proxy redirects: %s", err))
	}
	cancel()

	if option.Config.IsFlannelMasterDeviceSet() &&
		option.Config.FlannelUninstallOnExit {
		ep.DeleteBPFProgramLocked()
	}

	ep.BuildMutex.Unlock()

	return errs
}

func (d *Daemon) DeleteEndpoint(id string) (int, error) {
	if ep, err := endpointmanager.Lookup(id); err != nil {
		return 0, api.Error(DeleteEndpointIDInvalidCode, err)
	} else if ep == nil {
		return 0, api.New(DeleteEndpointIDNotFoundCode, "endpoint not found")
	} else if err = endpoint.APICanModify(ep); err != nil {
		return 0, api.Error(DeleteEndpointIDInvalidCode, err)
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
		if apierr, ok := err.(*api.APIError); ok {
			return apierr
		}
		return api.Error(DeleteEndpointIDErrorsCode, err)
	} else if nerr > 0 {
		return NewDeleteEndpointIDErrors().WithPayload(int64(nerr))
	} else {
		return NewDeleteEndpointIDOK()
	}
}

// EndpointUpdate updates the options of the given endpoint and regenerates the endpoint
func (d *Daemon) EndpointUpdate(id string, cfg *models.EndpointConfigurationSpec) error {
	ep, err := endpointmanager.Lookup(id)
	if err != nil {
		return api.Error(PatchEndpointIDInvalidCode, err)
	} else if ep == nil {
		return api.New(PatchEndpointIDConfigNotFoundCode, "endpoint %s not found", id)
	} else if err = endpoint.APICanModify(ep); err != nil {
		return api.Error(PatchEndpointIDInvalidCode, err)
	}

	if err := ep.Update(d, cfg); err != nil {
		switch err.(type) {
		case endpoint.UpdateValidationError:
			return api.Error(PatchEndpointIDConfigInvalidCode, err)
		default:
			return api.Error(PatchEndpointIDConfigFailedCode, err)
		}
	}
	if err := ep.RLockAlive(); err != nil {
		return api.Error(PatchEndpointIDNotFoundCode, err)
	}
	endpointmanager.UpdateReferences(ep)
	ep.RUnlock()

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
	if err := d.EndpointUpdate(params.ID, params.EndpointConfiguration); err != nil {
		if apierr, ok := err.(*api.APIError); ok {
			return apierr
		}
		return api.Error(PatchEndpointIDFailedCode, err)
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
		return api.Error(GetEndpointIDInvalidCode, err)
	} else if ep == nil {
		return NewGetEndpointIDConfigNotFound()
	} else {
		cfgStatus := &models.EndpointConfigurationStatus{
			Realized: &models.EndpointConfigurationSpec{
				LabelConfiguration: &models.LabelConfigurationSpec{
					User: ep.OpLabels.Custom.GetModel(),
				},
				Options: *ep.Options.GetMutableModel(),
			},
			Immutable: *ep.Options.GetImmutableModel(),
		}

		return NewGetEndpointIDConfigOK().WithPayload(cfgStatus)
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
		return api.Error(GetEndpointIDInvalidCode, err)
	}
	if ep == nil {
		return NewGetEndpointIDLabelsNotFound()
	}

	if err := ep.RLockAlive(); err != nil {
		return api.Error(GetEndpointIDInvalidCode, err)
	}
	spec := &models.LabelConfigurationSpec{
		User: ep.OpLabels.Custom.GetModel(),
	}

	cfg := models.LabelConfiguration{
		Spec: spec,
		Status: &models.LabelConfigurationStatus{
			Realized:         spec,
			SecurityRelevant: ep.OpLabels.OrchestrationIdentity.GetModel(),
			Derived:          ep.OpLabels.OrchestrationInfo.GetModel(),
			Disabled:         ep.OpLabels.Disabled.GetModel(),
		},
	}
	ep.RUnlock()

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
		return api.Error(GetEndpointIDLogInvalidCode, err)
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
		return api.Error(GetEndpointIDHealthzInvalidCode, err)
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

// modifyEndpointIdentityLabelsFromAPI adds and deletes the given labels on given endpoint ID.
// Performs checks for whether the endpoint may be modified by an API call.
// The received `add` and `del` labels will be filtered with the valid label prefixes.
// The `add` labels take precedence over `del` labels, this means if the same
// label is set on both `add` and `del`, that specific label will exist in the
// endpoint's labels.
// Returns an HTTP response code and an error msg (or nil on success).
func (d *Daemon) modifyEndpointIdentityLabelsFromAPI(id string, add, del labels.Labels) (int, error) {
	addLabels, delLabels, ok := checkLabels(add, del)
	if !ok {
		return 0, nil
	}
	if lbls := addLabels.FindReserved(); lbls != nil {
		return PatchEndpointIDLabelsUpdateFailedCode, fmt.Errorf("Not allowed to add reserved labels: %s", lbls)
	} else if lbls := delLabels.FindReserved(); lbls != nil {
		return PatchEndpointIDLabelsUpdateFailedCode, fmt.Errorf("Not allowed to delete reserved labels: %s", lbls)
	}

	ep, err := endpointmanager.Lookup(id)
	if err != nil {
		return PatchEndpointIDInvalidCode, err
	}
	if ep == nil {
		return PatchEndpointIDLabelsNotFoundCode, fmt.Errorf("Endpoint ID %s not found", id)
	}
	if err = endpoint.APICanModify(ep); err != nil {
		return PatchEndpointIDInvalidCode, err
	}

	if err := ep.ModifyIdentityLabels(d, addLabels, delLabels); err != nil {
		return PatchEndpointIDLabelsNotFoundCode, err
	}

	return PatchEndpointIDLabelsOKCode, nil
}

type putEndpointIDLabels struct {
	daemon *Daemon
}

func NewPatchEndpointIDLabelsHandler(d *Daemon) PatchEndpointIDLabelsHandler {
	return &putEndpointIDLabels{daemon: d}
}

func (h *putEndpointIDLabels) Handle(params PatchEndpointIDLabelsParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("PATCH /endpoint/{id}/labels request")

	d := h.daemon
	mod := params.Configuration
	lbls := labels.NewLabelsFromModel(mod.User)

	ep, err := endpointmanager.Lookup(params.ID)
	if err != nil {
		return api.Error(PutEndpointIDInvalidCode, err)
	} else if ep == nil {
		return NewPatchEndpointIDLabelsNotFound()
	}

	if err := ep.RLockAlive(); err != nil {
		return api.Error(PutEndpointIDInvalidCode, err)
	}

	add, del := ep.OpLabels.SplitUserLabelChanges(lbls)
	ep.RUnlock()

	code, err := d.modifyEndpointIdentityLabelsFromAPI(params.ID, add, del)
	if err != nil {
		return api.Error(code, err)
	}
	return NewPatchEndpointIDLabelsOK()
}
