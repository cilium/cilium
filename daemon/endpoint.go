// Copyright 2016-2020 Authors of Cilium
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
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/endpoint"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/k8s"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/option"

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
	resEPs := h.d.getEndpointList(params)

	if params.Labels != nil && len(resEPs) == 0 {
		return NewGetEndpointNotFound()
	}

	return NewGetEndpointOK().WithPayload(resEPs)
}

func (d *Daemon) getEndpointList(params GetEndpointParams) []*models.Endpoint {
	maxGoroutines := runtime.NumCPU()
	var (
		epWorkersWg, epsAppendWg sync.WaitGroup
		convertedLabels          labels.Labels
		resEPs                   []*models.Endpoint
	)

	if params.Labels != nil {
		// Convert params.Labels to model that we can compare with the endpoint's labels.
		convertedLabels = labels.NewLabelsFromModel(params.Labels)
	}

	eps := d.endpointManager.GetEndpoints()
	if len(eps) < maxGoroutines {
		maxGoroutines = len(eps)
	}
	epsCh := make(chan *endpoint.Endpoint, maxGoroutines)
	epModelsCh := make(chan *models.Endpoint, maxGoroutines)

	epWorkersWg.Add(maxGoroutines)
	for i := 0; i < maxGoroutines; i++ {
		// Run goroutines to process each endpoint and the corresponding model.
		// The obtained endpoint model is sent to the endpoint models channel from
		// where it will be aggregated later.
		go func(wg *sync.WaitGroup, epModelsChan chan<- *models.Endpoint, epsChan <-chan *endpoint.Endpoint) {
			for ep := range epsChan {
				if ep.HasLabels(convertedLabels) {
					epModelsChan <- ep.GetModel()
				}
			}
			wg.Done()
		}(&epWorkersWg, epModelsCh, epsCh)
	}

	// Send the endpoints to be aggregated a models to the endpoint channel.
	go func(epsChan chan<- *endpoint.Endpoint, eps []*endpoint.Endpoint) {
		for _, ep := range eps {
			epsChan <- ep
		}
		close(epsChan)
	}(epsCh, eps)

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

	epWorkersWg.Wait()
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

	ep, err := h.d.endpointManager.Lookup(params.ID)

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

// fetchK8sLabelsAndAnnotations wraps the k8s package to fetch and provide
// endpoint metadata. It implements endpoint.MetadataResolverCB.
func (d *Daemon) fetchK8sLabelsAndAnnotations(nsName, podName string) (labels.Labels, labels.Labels, map[string]string, error) {
	p, err := d.k8sWatcher.GetCachedPod(nsName, podName)
	if err != nil {
		return nil, nil, nil, err
	}
	ns, err := d.k8sWatcher.GetCachedNamespace(nsName)
	if err != nil {
		return nil, nil, nil, err
	}

	lbls, annotations, err := k8s.GetPodMetadata(ns, p)
	if err != nil {
		return nil, nil, nil, err
	}

	k8sLbls := labels.Map2Labels(lbls, labels.LabelSourceK8s)
	identityLabels, infoLabels := labels.FilterLabels(k8sLbls)
	return identityLabels, infoLabels, annotations, nil
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
	if option.Config.EnableEndpointRoutes {
		if epTemplate.DatapathConfiguration == nil {
			epTemplate.DatapathConfiguration = &models.EndpointDatapathConfiguration{}
		}

		// Indicate to insert a per endpoint route instead of routing
		// via cilium_host interface
		epTemplate.DatapathConfiguration.InstallEndpointRoute = true

		// Since routing occurs via endpoint interface directly, BPF
		// program is needed on that device at egress as BPF program on
		// cilium_host interface is bypassed
		epTemplate.DatapathConfiguration.RequireEgressProg = true

		// Delegate routing to the Linux stack rather than tail-calling
		// between BPF programs.
		disabled := false
		epTemplate.DatapathConfiguration.RequireRouting = &disabled
	}

	ep, err := endpoint.NewEndpointFromChangeModel(d.ctx, d, d.l7Proxy, d.identityAllocator, epTemplate)
	if err != nil {
		return invalidDataError(ep, fmt.Errorf("unable to parse endpoint parameters: %s", err))
	}

	oldEp := d.endpointManager.LookupCiliumID(ep.ID)
	if oldEp != nil {
		return invalidDataError(ep, fmt.Errorf("endpoint ID %d already exists", ep.ID))
	}

	oldEp = d.endpointManager.LookupContainerID(ep.GetContainerID())
	if oldEp != nil {
		return invalidDataError(ep, fmt.Errorf("endpoint for container %s already exists", ep.GetContainerID()))
	}

	var checkIDs []string

	if ep.IPv4.IsSet() {
		checkIDs = append(checkIDs, endpointid.NewID(endpointid.IPv4Prefix, ep.IPv4.String()))
	}

	if ep.IPv6.IsSet() {
		checkIDs = append(checkIDs, endpointid.NewID(endpointid.IPv6Prefix, ep.IPv6.String()))
	}

	for _, id := range checkIDs {
		oldEp, err := d.endpointManager.Lookup(id)
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

		addLabels, _ = labels.FilterLabels(addLabels)
		if len(addLabels) == 0 {
			return invalidDataError(ep, fmt.Errorf("no valid labels provided"))
		}
	}

	if ep.K8sNamespaceAndPodNameIsSet() && k8s.IsEnabled() {
		identityLabels, info, _, err := d.fetchK8sLabelsAndAnnotations(ep.K8sNamespace, ep.K8sPodName)
		if err != nil {
			ep.Logger("api").WithError(err).Warning("Unable to fetch kubernetes labels")
		} else {
			addLabels.MergeLabels(identityLabels)
			infoLabels.MergeLabels(info)
		}
	}

	// The following docs describe the cases where the init identity is used:
	// http://docs.cilium.io/en/latest/policy/lifecycle/#init-identity
	if len(addLabels) == 0 {
		// If the endpoint has no labels, give the endpoint a special identity with
		// label reserved:init so we can generate a custom policy for it until we
		// get its actual identity.
		addLabels = labels.Labels{
			labels.IDNameInit: labels.NewLabel(labels.IDNameInit, "", labels.LabelSourceReserved),
		}
	}

	// Static pods (mirror pods) might be configured before the apiserver
	// is available or has received the notification that includes the
	// static pod's labels. In this case, start a controller to attempt to
	// resolve the labels.
	k8sLabelsConfigured := true
	if ep.K8sNamespaceAndPodNameIsSet() && k8s.IsEnabled() {
		// If there are labels, but no pod namespace, then it's
		// likely that there are no k8s labels at all. Resolve.
		if _, k8sLabelsConfigured = addLabels[k8sConst.PodNamespaceLabel]; !k8sLabelsConfigured {
			ep.RunMetadataResolver(d.fetchK8sLabelsAndAnnotations)
		}
	}

	err = d.endpointManager.AddEndpoint(d, ep, "Create endpoint from API PUT")
	if err != nil {
		return d.errorDuringCreation(ep, fmt.Errorf("unable to insert endpoint into manager: %s", err))
	}

	// We need to update the the visibility policy after adding the endpoint in
	// the endpoint manager because the endpoint manager create the endpoint
	// queue of the endpoint. If we execute this function before the endpoint
	// manager creates the endpoint queue the operation will fail.
	if ep.K8sNamespaceAndPodNameIsSet() && k8s.IsEnabled() && k8sLabelsConfigured {
		ep.UpdateVisibilityPolicy(func(ns, podName string) (proxyVisibility string, err error) {
			p, err := d.k8sWatcher.GetCachedPod(ns, podName)
			if err != nil {
				return "", err
			}

			return p.Annotations[annotation.ProxyVisibility], nil
		})
	}

	ep.UpdateLabels(ctx, addLabels, infoLabels, true)

	select {
	case <-ctx.Done():
		return d.errorDuringCreation(ep, fmt.Errorf("request cancelled while resolving identity"))
	default:
	}

	// Now that we have ep.ID we can pin the map from this point. This
	// also has to happen before the first build took place.
	if err = ep.PinDatapathMap(); err != nil {
		return d.errorDuringCreation(ep, fmt.Errorf("unable to pin datapath maps: %s", err))
	}

	if err := ep.RegenerateAfterCreation(ctx, epTemplate.SyncBuildEndpoint); err != nil {
		return d.errorDuringCreation(ep, err)
	}

	// The endpoint has been successfully created, stop the expiration
	// timers of all attached IPs
	if addressing := epTemplate.Addressing; addressing != nil {
		if uuid := addressing.IPV4ExpirationUUID; uuid != "" {
			if ip := net.ParseIP(addressing.IPV4); ip != nil {
				if err := d.ipam.StopExpirationTimer(ip, uuid); err != nil {
					return d.errorDuringCreation(ep, err)
				}
			}
		}
		if uuid := addressing.IPV6ExpirationUUID; uuid != "" {
			if ip := net.ParseIP(addressing.IPV6); ip != nil {
				if err := d.ipam.StopExpirationTimer(ip, uuid); err != nil {
					return d.errorDuringCreation(ep, err)
				}
			}
		}
	}

	return ep, 0, nil
}

func (h *putEndpointID) Handle(params PutEndpointIDParams) middleware.Responder {
	if ep := params.Endpoint; ep != nil {
		log.WithField("endpoint", logfields.Repr(*ep)).Debug("PUT /endpoint/{id} request")
	} else {
		log.WithField(logfields.Params, logfields.Repr(params)).Debug("PUT /endpoint/{id} request")
	}
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

// validPatchTransitionState checks whether the state to which the provided
// model specifies is one to which an Endpoint can transition as part of a
// call to PATCH on an Endpoint.
func validPatchTransitionState(state models.EndpointState) bool {
	switch string(state) {
	case "", endpoint.StateWaitingForIdentity, endpoint.StateReady:
		return true
	}
	return false
}

func (h *patchEndpointID) Handle(params PatchEndpointIDParams) middleware.Responder {
	scopedLog := log.WithField(logfields.Params, logfields.Repr(params))
	if ep := params.Endpoint; ep != nil {
		scopedLog = scopedLog.WithField("endpoint", logfields.Repr(*ep))
	}
	scopedLog.Debug("PATCH /endpoint/{id} request")

	epTemplate := params.Endpoint

	// Validate the template. Assignment afterwards is atomic.
	// Note: newEp's labels are ignored.
	newEp, err2 := endpoint.NewEndpointFromChangeModel(h.d.ctx, h.d, h.d.l7Proxy, h.d.identityAllocator, epTemplate)
	if err2 != nil {
		return api.Error(PutEndpointIDInvalidCode, err2)
	}

	var validStateTransition bool

	// Log invalid state transitions, but do not error out for backwards
	// compatibility.
	if !validPatchTransitionState(epTemplate.State) {
		scopedLog.Debugf("PATCH /endpoint/{id} to invalid state '%s'", epTemplate.State)
	} else {
		validStateTransition = true
	}

	ep, err := h.d.endpointManager.Lookup(params.ID)
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
	reason, err := ep.ProcessChangeRequest(newEp, validStateTransition)
	if err != nil {
		return NewPatchEndpointIDNotFound()
	}

	if reason != "" {
		if err := ep.RegenerateWait(reason); err != nil {
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
		NoIPRelease: ep.DatapathConfiguration.ExternalIpam,
	})
	for _, err := range errs {
		scopedLog.WithError(err).Warn("Ignoring error while deleting endpoint")
	}
	return len(errs)
}

// NotifyMonitorDeleted notifies the monitor that an endpoint has been deleted.
func (d *Daemon) NotifyMonitorDeleted(ep *endpoint.Endpoint) {
	repr, err := monitorAPI.EndpointDeleteRepr(ep)
	// Ignore endpoint deletion if EndpointDeleteRepr != nil
	if err == nil {
		d.SendNotification(monitorAPI.AgentNotifyEndpointDeleted, repr)
	}
}

// deleteEndpointQuiet sets the endpoint into disconnecting state and removes
// it from Cilium, releasing all resources associated with it such as its
// visibility in the endpointmanager, its BPF programs and maps, (optional) IP,
// L7 policy configuration, directories and controllers.
//
// Specific users such as the cilium-health EP may choose not to release the IP
// when deleting the endpoint. Most users should pass true for releaseIP.
func (d *Daemon) deleteEndpointQuiet(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) []error {
	return ep.Delete(d, d.ipam, d.endpointManager, conf)
}

func (d *Daemon) DeleteEndpoint(id string) (int, error) {
	if ep, err := d.endpointManager.Lookup(id); err != nil {
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
	ep, err := d.endpointManager.Lookup(id)
	if err != nil {
		return api.Error(PatchEndpointIDInvalidCode, err)
	} else if ep == nil {
		return api.New(PatchEndpointIDConfigNotFoundCode, "endpoint %s not found", id)
	} else if err = endpoint.APICanModify(ep); err != nil {
		return api.Error(PatchEndpointIDInvalidCode, err)
	}

	if err := ep.Update(cfg); err != nil {
		switch err.(type) {
		case endpoint.UpdateValidationError:
			return api.Error(PatchEndpointIDConfigInvalidCode, err)
		default:
			return api.Error(PatchEndpointIDConfigFailedCode, err)
		}
	}
	if err := ep.UpdateReferences(d.endpointManager); err != nil {
		return api.Error(PatchEndpointIDNotFoundCode, err)
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

	ep, err := h.daemon.endpointManager.Lookup(params.ID)
	if err != nil {
		return api.Error(GetEndpointIDInvalidCode, err)
	} else if ep == nil {
		return NewGetEndpointIDConfigNotFound()
	} else {
		cfgStatus := ep.GetConfigurationStatus()

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

	ep, err := h.daemon.endpointManager.Lookup(params.ID)
	if err != nil {
		return api.Error(GetEndpointIDInvalidCode, err)
	}
	if ep == nil {
		return NewGetEndpointIDLabelsNotFound()
	}

	cfg, err := ep.GetLabelsModel()

	if err != nil {
		return api.Error(GetEndpointIDInvalidCode, err)
	}

	return NewGetEndpointIDLabelsOK().WithPayload(cfg)
}

type getEndpointIDLog struct {
	d *Daemon
}

func NewGetEndpointIDLogHandler(d *Daemon) GetEndpointIDLogHandler {
	return &getEndpointIDLog{d: d}
}

func (h *getEndpointIDLog) Handle(params GetEndpointIDLogParams) middleware.Responder {
	log.WithField(logfields.EndpointID, params.ID).Debug("GET /endpoint/{id}/log request")

	ep, err := h.d.endpointManager.Lookup(params.ID)

	if err != nil {
		return api.Error(GetEndpointIDLogInvalidCode, err)
	} else if ep == nil {
		return NewGetEndpointIDLogNotFound()
	} else {
		return NewGetEndpointIDLogOK().WithPayload(ep.GetStatusModel())
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

	ep, err := h.d.endpointManager.Lookup(params.ID)

	if err != nil {
		return api.Error(GetEndpointIDHealthzInvalidCode, err)
	} else if ep == nil {
		return NewGetEndpointIDHealthzNotFound()
	} else {
		return NewGetEndpointIDHealthzOK().WithPayload(ep.GetHealthModel())
	}
}

// modifyEndpointIdentityLabelsFromAPI adds and deletes the given labels on given endpoint ID.
// Performs checks for whether the endpoint may be modified by an API call.
// The received `add` and `del` labels will be filtered with the valid label prefixes.
// The `add` labels take precedence over `del` labels, this means if the same
// label is set on both `add` and `del`, that specific label will exist in the
// endpoint's labels.
// Returns an HTTP response code and an error msg (or nil on success).
func (d *Daemon) modifyEndpointIdentityLabelsFromAPI(id string, add, del labels.Labels) (int, error) {
	addLabels, _ := labels.FilterLabels(add)
	delLabels, _ := labels.FilterLabels(del)
	if lbls := addLabels.FindReserved(); lbls != nil {
		return PatchEndpointIDLabelsUpdateFailedCode, fmt.Errorf("Not allowed to add reserved labels: %s", lbls)
	} else if lbls := delLabels.FindReserved(); lbls != nil {
		return PatchEndpointIDLabelsUpdateFailedCode, fmt.Errorf("Not allowed to delete reserved labels: %s", lbls)
	}

	ep, err := d.endpointManager.Lookup(id)
	if err != nil {
		return PatchEndpointIDInvalidCode, err
	}
	if ep == nil {
		return PatchEndpointIDLabelsNotFoundCode, fmt.Errorf("Endpoint ID %s not found", id)
	}
	if err = endpoint.APICanModify(ep); err != nil {
		return PatchEndpointIDInvalidCode, err
	}

	if err := ep.ModifyIdentityLabels(addLabels, delLabels); err != nil {
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

	ep, err := d.endpointManager.Lookup(params.ID)
	if err != nil {
		return api.Error(PutEndpointIDInvalidCode, err)
	} else if ep == nil {
		return NewPatchEndpointIDLabelsNotFound()
	}

	add, del, err := ep.ApplyUserLabelChanges(lbls)
	if err != nil {
		return api.Error(PutEndpointIDInvalidCode, err)
	}

	code, err := d.modifyEndpointIdentityLabelsFromAPI(params.ID, add, del)
	if err != nil {
		return api.Error(code, err)
	}
	return NewPatchEndpointIDLabelsOK()
}

// QueueEndpointBuild waits for a "build permit" for the endpoint
// identified by 'epID'. This function blocks until the endpoint can
// start building.  The returned function must then be called to
// release the "build permit" when the most resource intensive parts
// of the build are done. The returned function is idempotent, so it
// may be called more than once. Returns a nil function if the caller should NOT
// start building the endpoint. This may happen due to a build being
// queued for the endpoint already, or due to the wait for the build
// permit being canceled. The latter case happens when the endpoint is
// being deleted. Returns an error if the build permit could not be acquired.
func (d *Daemon) QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error) {
	// Acquire build permit. This may block.
	err := d.buildEndpointSem.Acquire(ctx, 1)

	if err != nil {
		return nil, err // Acquire failed
	}

	// Acquire succeeded, but the context was canceled after?
	if ctx.Err() != nil {
		d.buildEndpointSem.Release(1)
		return nil, ctx.Err()
	}

	// At this point the build permit has been acquired. It must
	// be released by the caller by calling the returned function
	// when the heavy lifting of the build is done.
	// Using sync.Once to make the returned function idempotent.
	var once sync.Once
	doneFunc := func() {
		once.Do(func() {
			d.buildEndpointSem.Release(1)
		})
	}
	return doneFunc, nil
}
