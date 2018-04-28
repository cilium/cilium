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

package endpoint

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/controller"
	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/sirupsen/logrus"
)

// optionEnabled  and optionDisabled are used
// to fill the models.ConfigurationMap opt state
const (
	optionEnabled  = "enabled"
	optionDisabled = "disabled"
)

// ProxyID returns a unique string to identify a proxy mapping.
func (e *Endpoint) ProxyID(l4 *policy.L4Filter) string {
	return policy.ProxyID(e.ID, l4.Ingress, string(l4.Protocol), uint16(l4.Port))
}

func getSecurityIdentities(labelsMap *identityPkg.IdentityCache, selector *api.EndpointSelector) []identityPkg.NumericIdentity {
	identities := []identityPkg.NumericIdentity{}
	for idx, labels := range *labelsMap {
		if selector.Matches(labels) {
			log.WithFields(logrus.Fields{
				logfields.IdentityLabels: labels,
				logfields.L4PolicyID:     idx,
			}).Debug("L4 Policy matches")
			identities = append(identities, idx)
		}
	}

	return identities
}

type PolicyKeyMeta struct {
	ID               uint32
	DPort            uint16
	Proto            uint8
	TrafficDirection policymap.TrafficDirection
}

// convertL4FilterToPolicyMapKeys adds the given l4 filter to the endpoint.
// Returns the number of errors that occurred while when applying the
// policy.
// Applies for L3-dependent L4, and not for L4-only policy.
func (e *Endpoint) convertL4FilterToPolicyMapKeys(identities *identityPkg.IdentityCache,
	filter *policy.L4Filter, direction policymap.TrafficDirection) []PolicyKeyMeta {

	keysToAdd := []PolicyKeyMeta{}

	port := uint16(filter.Port)
	proto := uint8(filter.U8Proto)

	for _, sel := range filter.Endpoints {
		for _, id := range getSecurityIdentities(identities, &sel) {
			srcID := id.Uint32()
			keyToAdd := PolicyKeyMeta{
				ID:               srcID,
				DPort:            port,
				Proto:            proto,
				TrafficDirection: direction,
			}
			keysToAdd = append(keysToAdd, keyToAdd)
		}
	}
	return keysToAdd
}

func (e *Endpoint) computeDesiredL4PolicyMapEntries(desiredL4Policy *policy.L4Policy) (keysToAdd map[PolicyKeyMeta]struct{}) {

	keysToAdd = map[PolicyKeyMeta]struct{}{}

	if desiredL4Policy == nil {
		return
	}

	for _, filter := range desiredL4Policy.Ingress {
		keysFromFilter := e.convertL4FilterToPolicyMapKeys(e.IdentityCache, &filter, policymap.Ingress)
		for _, keyFromFilter := range keysFromFilter {
			keysToAdd[keyFromFilter] = struct{}{}
		}
	}

	for _, filter := range desiredL4Policy.Egress {
		keysFromFilter := e.convertL4FilterToPolicyMapKeys(e.IdentityCache, &filter, policymap.Egress)
		for _, keyFromFilter := range keysFromFilter {
			keysToAdd[keyFromFilter] = struct{}{}
		}
	}

	return
}

func getIdentityCache() (*identityPkg.IdentityCache, error) {
	labelsMap := identityPkg.GetIdentityCache()

	reservedIDs := identityPkg.GetReservedIdentities()
	//reservedIDs := policy.GetReservedIDs()
	var k identityPkg.NumericIdentity
	var v *identityPkg.Identity
	for k, v = range reservedIDs {
		lbls := v.Labels.ToSlice()
		if lbls == nil || len(lbls) == 0 {
			return nil, fmt.Errorf("unable to resolve reserved identity")
		}
		labelsMap[k] = lbls
	}

	return &labelsMap, nil
}

// Must be called with global endpoint.Mutex held
func (e *Endpoint) resolveL4Policy(owner Owner, repo *policy.Repository) error {

	ingressCtx := policy.SearchContext{
		To: e.SecurityIdentity.Labels.ToSlice(),
	}

	egressCtx := policy.SearchContext{
		From: e.SecurityIdentity.Labels.ToSlice(),
	}

	if owner.TracingEnabled() {
		ingressCtx.Trace = policy.TRACE_ENABLED
		egressCtx.Trace = policy.TRACE_ENABLED
	}

	newL4IngressPolicy, err := repo.ResolveL4IngressPolicy(&ingressCtx)
	if err != nil {
		return err
	}

	newL4EgressPolicy, err := repo.ResolveL4EgressPolicy(&egressCtx)
	if err != nil {
		return err
	}

	newL4Policy := &policy.L4Policy{Ingress: *newL4IngressPolicy,
		Egress: *newL4EgressPolicy}

	if reflect.DeepEqual(e.RealizedL4Policy, newL4Policy) {
		return nil
	}

	e.DesiredL4Policy = newL4Policy

	return nil
}

// Must be called with global endpoint.Mutex held
// Returns a boolean to signalize if the policy was changed;
// and a set of entries to add to the BPF map for this endpoint
func (e *Endpoint) calculateDesiredPolicyMapState(owner Owner, repo *policy.Repository) (changed bool) {

	if e.desiredMapState == nil {
		e.desiredMapState = make(map[PolicyKeyMeta]struct{})
	}

	desiredPolicyKeys := e.computeDesiredL4PolicyMapEntries(e.DesiredL4Policy)

	// Determine if we have to allow traffic to the host identity.
	if owner.AlwaysAllowLocalhost() || e.DesiredL4Policy.HasRedirect() {
		keyToAdd := PolicyKeyMeta{
			ID:               identityPkg.ReservedIdentityHost.Uint32(),
			TrafficDirection: policymap.Ingress,
		}
		desiredPolicyKeys[keyToAdd] = struct{}{}
	}

	ingressCtx := policy.SearchContext{
		To: e.SecurityIdentity.Labels.ToSlice(),
	}
	egressCtx := policy.SearchContext{
		From: e.SecurityIdentity.Labels.ToSlice(),
	}

	if owner.TracingEnabled() {
		ingressCtx.Trace = policy.TRACE_ENABLED
		egressCtx.Trace = policy.TRACE_ENABLED
	}

	// Determine whether this identity can reach other identities on ingress
	// and egress via L3 only.
	for identity, labels := range *e.IdentityCache {
		ingressCtx.From = labels
		egressCtx.To = labels

		ingressAccess := repo.AllowsIngressLabelAccess(&ingressCtx)
		if ingressAccess == api.Allowed {
			keyToAdd := PolicyKeyMeta{
				ID:               identity.Uint32(),
				TrafficDirection: policymap.Ingress,
			}
			desiredPolicyKeys[keyToAdd] = struct{}{}
		}

		egressAccess := repo.AllowsEgressLabelAccess(&egressCtx)
		if egressAccess == api.Allowed {
			keyToAdd := PolicyKeyMeta{
				ID:               identity.Uint32(),
				TrafficDirection: policymap.Egress,
			}
			desiredPolicyKeys[keyToAdd] = struct{}{}
		}
	}

	// Determine whether state necessitates change from policymap perspective.
	// If any policy key in the list of desired keys to add is not in the
	// list of keys that were previously computed for this endpoint, that means
	// that there was a policy change.
	for k := range desiredPolicyKeys {
		if _, ok := e.desiredMapState[k]; !ok {
			changed = true
			break
		}
	}

	// Set new desired state now that we have calculated whether there was a change
	// or not.
	e.desiredMapState = make(map[PolicyKeyMeta]struct{})
	for k, v := range desiredPolicyKeys {
		e.desiredMapState[k] = v
	}

	return
}

// Must be called with global repo.Mutex, e.Mutex, and c.Mutex held
func (e *Endpoint) regenerateL3CIDRPolicy(owner Owner, repo *policy.Repository, revision uint64) (bool, error) {

	ctx := policy.SearchContext{
		To: e.SecurityIdentity.Labels.ToSlice(),
	}
	if owner.TracingEnabled() {
		ctx.Trace = policy.TRACE_ENABLED
	}
	newL3policy := repo.ResolveCIDRPolicy(&ctx)
	// Perform the validation on the new policy
	err := newL3policy.Validate()
	valid := err == nil

	if valid {
		if reflect.DeepEqual(e.L3Policy, newL3policy) {
			e.getLogger().Debug("No change in CIDR policy")
			return false, nil
		}
		e.L3Policy = newL3policy
	}

	return valid, err
}

// IngressOrEgressIsEnforced returns true if either ingress or egress is in
// enforcement mode or if the global policy enforcement is enabled.
func (e *Endpoint) IngressOrEgressIsEnforced() bool {
	return policy.GetPolicyEnabled() == AlwaysEnforce ||
		e.Opts.IsEnabled(OptionIngressPolicy) ||
		e.Opts.IsEnabled(OptionEgressPolicy)
}

func (e *Endpoint) updateNetworkPolicy(owner Owner) error {
	// Skip updating the NetworkPolicy if no policy has been calculated.
	// This breaks a circular dependency between configuring NetworkPolicies in
	// sidecar Envoy proxies and those proxies needing network connectivity
	// to get their initial configuration, which is required for them to ACK
	// the NetworkPolicies.
	if !e.policyCalculated {
		return nil
	}

	// Compute the set of identities explicitly denied by policy.
	// This loop is similar to the one in calculateDesiredPolicyMapState called
	// above, but this set only contains the identities with "Denied" verdicts.
	ctx := policy.SearchContext{
		To: e.SecurityIdentity.Labels.ToSlice(),
	}
	if owner.TracingEnabled() {
		ctx.Trace = policy.TRACE_ENABLED
	}
	deniedIngressIdentities := make(map[identityPkg.NumericIdentity]bool)
	for srcID, srcLabels := range *e.IdentityCache {
		ctx.From = srcLabels
		e.getLogger().WithFields(logrus.Fields{
			logfields.PolicyID: srcID,
			"ctx":              ctx,
		}).Debug("Evaluating context for source PolicyID")
		repo := owner.GetPolicyRepository()
		if repo.CanReachIngressRLocked(&ctx) == api.Denied {
			// Denied explicitly by fromRequires clause.
			deniedIngressIdentities[srcID] = true
		}
	}

	// Reset SearchContext to reflect change in directionality.
	ctx = policy.SearchContext{
		From: e.SecurityIdentity.Labels.ToSlice(),
	}

	deniedEgressIdentities := make(map[identityPkg.NumericIdentity]bool)
	for dstID, dstLabels := range *e.IdentityCache {
		ctx.To = dstLabels
		e.getLogger().WithFields(logrus.Fields{
			logfields.PolicyID: dstID,
			"ctx":              ctx,
		}).Debug("Evaluating context for destination PolicyID")
		repo := owner.GetPolicyRepository()
		if repo.CanReachEgressRLocked(&ctx) == api.Denied {
			// Denied explicitly by toRequires clause.
			deniedEgressIdentities[dstID] = true
		}
	}

	// Publish the updated policy to L7 proxies.
	err := owner.UpdateNetworkPolicy(e, e.DesiredL4Policy, *e.IdentityCache, deniedIngressIdentities, deniedEgressIdentities)
	if err != nil {
		return err
	}

	return nil
}

// regeneratePolicy regenerates endpoint's policy if needed and returns
// whether the BPF for the given endpoint should be regenerated. Only
// called when e.Consumable != nil.
//
// In a typical workflow this is first called to regenerate the policy
// (if needed), and second time when the BPF program is
// regenerated. The second step is usually unnecessary and may be
// optimized away by the revision checks.  However, if there has been
// a further policy update between the first and second calls, the
// second call will update the policy just before regenerating the BPF
// programs to avoid needing to regenerate BPF programs again right
// after.
//
// Policy changes are tracked so that only endpoints affected by the
// policy change need to have their BPF programs regenerated.
//
// Policy generation may fail, and in that case we exit before
// actually changing the policy in any way, so that the last policy
// remains fully in effect if the new policy can not be
// implemented. This is done on a per endpoint-basis, however, and it is
// possible that policy update succeeds for some endpoints, while it
// fails for other endpoints.
//
// Returns:
//  - changed: true if the policy was changed for this endpoint;
//  - err: error in case of an error.
// Must be called with endpoint mutex held.
func (e *Endpoint) regeneratePolicy(owner Owner, opts models.ConfigurationMap) (bool, error) {
	// Dry mode does not regenerate policy via bpf regeneration, so we let it pass
	// through. Some bpf/redirect updates are skipped in that case.
	//
	// This can be cleaned up once we shift all bpf updates to regenerateBPF().
	if e.PolicyMap == nil && !owner.DryModeEnabled() {
		// First run always results in bpf generation
		// L4 policy generation assumes e.PolicyMap to exist, but it is only created
		// when bpf is generated for the first time. Until then we can't really compute
		// the policy. Bpf generation calls us again after PolicyMap is created.
		// In dry mode we are called with a nil PolicyMap.

		// We still need to apply any options if given.
		if opts != nil {
			e.applyOptsLocked(opts)
		}
		e.getLogger().Debug("marking policy as changed to trigger bpf generation as part of first build")
		return true, nil
	}

	e.getLogger().Debug("Starting regeneration of policy for endpoint...")

	// Collect label arrays before policy computation, as this can fail.
	identityCache, err := getIdentityCache()
	if err != nil {
		e.getLogger().WithError(err).Debug("Received error while evaluating policy")
		return false, err
	}
	// Use the old identityCache instance if the new one is still the same.
	// Later we can compare the pointers to figure out if labels have changed or not.
	if reflect.DeepEqual(e.IdentityCache, identityCache) {
		identityCache = e.IdentityCache
	}

	// Determine policy for endpoint based off of all rules in policy repository.
	repo := owner.GetPolicyRepository()
	repo.Mutex.RLock()
	revision := repo.GetRevision()
	defer repo.Mutex.RUnlock()

	// Recompute policy for this endpoint only if not already done for this revision.
	// Must recompute if labels have changed or option changes are requested.
	if !e.forcePolicyCompute && e.nextPolicyRevision >= revision &&
		identityCache == e.IdentityCache && opts == nil {

		e.getLogger().WithFields(logrus.Fields{
			"policyRevision.next":        e.nextPolicyRevision,
			"policyRevision.repo":        revision,
			"nextRevGreaterThanRealized": e.nextPolicyRevision > e.realizedPolicyRevision,
		}).Debug("skipping policy recalculation")
		// This revision already computed, but may still need to be applied to BPF
		return e.nextPolicyRevision > e.realizedPolicyRevision, nil
	}

	// Endpoints without a security identity are not accessible.
	if e.SecurityIdentity.ID == 0 {
		e.getLogger().Warn("Endpoint lacks identity, skipping policy calculation")
		return false, nil
	}

	err = e.resolveL4Policy(owner, repo)
	if err != nil {
		return false, err
	}

	// Calculate L3 (CIDR) policy.
	var cidrPolicyChanged bool
	if cidrPolicyChanged, err = e.regenerateL3CIDRPolicy(owner, repo, revision); err != nil {
		return false, err
	}

	optsChanged := e.applyConfiguration(owner, opts)

	// Determines changes needed for this endpoint's BPF PolicyMap

	e.IdentityCache = identityCache
	policyMapDesiredStateChanged := e.calculateDesiredPolicyMapState(owner, repo)

	var forcedPolicyChange bool

	// If we are in this function, then policy has been calculated.
	if !e.policyCalculated {
		e.getLogger().Debug("setting policyCalculated to true for endpoint")
		e.policyCalculated = true
		// Always trigger a regenerate after the first policy
		// calculation has been performed
		forcedPolicyChange = true
	}

	if e.forcePolicyCompute {
		forcedPolicyChange = true    // Options were changed by the caller.
		e.forcePolicyCompute = false // Policies just computed
		e.getLogger().Debug("Forced policy recalculation")
	}

	e.nextPolicyRevision = revision

	if !owner.DryModeEnabled() {
		e.syncPolicyWithDatapath()
	}

	// If no policy or options change occurred for this endpoint then the endpoint is
	// already running the latest revision, otherwise we have to wait for
	// the regeneration of the endpoint to complete.
	if !cidrPolicyChanged && !optsChanged && !policyMapDesiredStateChanged {
		e.setPolicyRevision(revision)
	}

	e.getLogger().WithFields(logrus.Fields{
		"cidrPolicyChanged":            cidrPolicyChanged,
		"optsChanged":                  optsChanged,
		"realizedPolicyRevision":       e.realizedPolicyRevision,
		"nextPolicyRevision":           e.nextPolicyRevision,
		"policyMapDesiredStateChanged": policyMapDesiredStateChanged,
		"forcedPolicyChange":           forcedPolicyChange,
	}).Debug("Done recomputing policy for this endpoint")

	changeInPolicy := optsChanged || cidrPolicyChanged || e.nextPolicyRevision > e.realizedPolicyRevision || forcedPolicyChange

	return changeInPolicy, nil
}

func (e *Endpoint) applyConfiguration(owner Owner, opts models.ConfigurationMap) (optionsChanged bool) {
	if opts == nil {
		opts = make(models.ConfigurationMap)
	}

	// Apply possible option changes before regenerating maps, as map regeneration
	// depends on the conntrack options
	if e.DesiredL4Policy != nil {
		if e.DesiredL4Policy.RequiresConntrack() {
			opts[OptionConntrack] = optionEnabled
		}
	}

	// Policy enforcement mode configuration.
	ingress, egress := owner.EnableEndpointPolicyEnforcement(e)

	opts[OptionIngressPolicy] = optionDisabled
	opts[OptionEgressPolicy] = optionDisabled

	if !ingress && !egress {
		e.getLogger().Debug("ingress and egress policy enforcement not enabled")
	} else {
		if ingress && egress {
			e.getLogger().Debug("policy enforcement for ingress and egress enabled")
			opts[OptionIngressPolicy] = optionEnabled
			opts[OptionEgressPolicy] = optionEnabled
		} else if ingress {
			e.getLogger().Debug("policy enforcement for ingress enabled")
			opts[OptionIngressPolicy] = optionEnabled
		} else {
			e.getLogger().Debug("policy enforcement for egress enabled")
			opts[OptionEgressPolicy] = optionEnabled
		}
	}

	return e.applyOptsLocked(opts)
}

// Called with e.Mutex UNlocked
func (e *Endpoint) regenerate(owner Owner, reason string) (retErr error) {
	metrics.EndpointCountRegenerating.Inc()
	defer func() {
		metrics.EndpointCountRegenerating.Dec()
		if retErr == nil {
			metrics.EndpointRegenerationCount.
				WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()
		} else {
			metrics.EndpointRegenerationCount.
				WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
		}
	}()

	e.BuildMutex.Lock()
	defer e.BuildMutex.Unlock()

	e.Mutex.RLock()
	e.getLogger().Debug("Regenerating endpoint...")
	e.Mutex.RUnlock()

	origDir := filepath.Join(owner.GetStateDir(), e.StringID())

	// This is the temporary directory to store the generated headers,
	// the original existing directory is not overwritten until the
	// entire generation process has succeeded.
	tmpDir := origDir + "_next"

	// Create temporary endpoint directory if it does not exist yet
	if err := os.MkdirAll(tmpDir, 0777); err != nil {
		return fmt.Errorf("Failed to create endpoint directory: %s", err)
	}

	defer func() {
		// Set to Ready, but only if no other changes are pending.
		// State will remain as waiting-to-regenerate if further
		// changes are needed. There should be an another regenerate
		// queued for taking care of it.
		e.Mutex.Lock()
		e.BuilderSetStateLocked(StateReady, "Completed endpoint regeneration with no pending regeneration requests")
		e.Mutex.Unlock()
	}()

	revision, err := e.regenerateBPF(owner, tmpDir, reason)

	// If generation fails, keep the directory around. If it ever succeeds
	// again, clean up this copy.
	failDir := tmpDir + "_fail"
	os.RemoveAll(failDir) // Most likely will not exist; ignore failure.
	if err != nil {
		e.getLogger().WithFields(logrus.Fields{
			logfields.Path: failDir,
		}).Warn("Generating BPF for endpoint failed, keeping stale directory.")
		os.Rename(tmpDir, failDir)
		return err
	}

	// Move the current endpoint directory to a backup location
	backupDir := origDir + "_stale"
	if err := os.Rename(origDir, backupDir); err != nil {
		os.RemoveAll(tmpDir)
		return fmt.Errorf("Unable to rename current endpoint directory: %s", err)
	}

	// Make temporary directory the new endpoint directory
	if err := os.Rename(tmpDir, origDir); err != nil {
		os.RemoveAll(tmpDir)

		if err2 := os.Rename(backupDir, origDir); err2 != nil {
			e.getLogger().WithFields(logrus.Fields{
				logfields.Path: backupDir,
			}).Warn("Restoring directory for endpoint failed, endpoint " +
				"is in inconsistent state. Keeping stale directory.")
			return err2
		}

		return fmt.Errorf("Restored original endpoint directory, atomic replace failed: %s", err)
	}

	os.RemoveAll(backupDir)

	// Mark the endpoint to be running the policy revision it was
	// compiled for
	e.bumpPolicyRevision(revision)

	e.getLogger().Info("Endpoint policy recalculated")

	return nil
}

// Regenerate forces the regeneration of endpoint programs & policy
// Should only be called with e.state == StateWaitingToRegenerate or with
// e.state == StateWaitingForIdentity
func (e *Endpoint) Regenerate(owner Owner, reason string) <-chan bool {
	newReq := &Request{
		ID:           uint64(e.ID),
		MyTurn:       make(chan bool),
		Done:         make(chan bool),
		ExternalDone: make(chan bool),
	}

	go func(owner Owner, req *Request, e *Endpoint) {
		buildSuccess := true

		e.Mutex.Lock()
		// This must be accessed in a locked section, so we grab it here.
		scopedLog := e.getLogger()
		e.Mutex.Unlock()

		// We should only queue the request after we use all the endpoint's
		// lock/unlock. Otherwise this can get a deadlock if the endpoint is
		// being deleted at the same time. More info PR-1777.
		owner.QueueEndpointBuild(req)

		isMyTurn, isMyTurnChanOK := <-req.MyTurn
		if isMyTurnChanOK && isMyTurn {
			scopedLog.Debug("Dequeued endpoint from build queue")

			if err := e.regenerate(owner, reason); err != nil {
				buildSuccess = false
				scopedLog.WithError(err).Warn("Regeneration of endpoint program failed")
				e.LogStatus(BPF, Failure, "Error regenerating endpoint: "+err.Error())
				owner.SendNotification(monitor.AgentNotifyEndpointRegenerateFail,
					e.getIDandLabels()+": "+err.Error())
			} else {
				buildSuccess = true
				e.LogStatusOK(BPF, "Successfully regenerated endpoint program due to "+reason)
				owner.SendNotification(monitor.AgentNotifyEndpointRegenerateSuccess, e.getIDandLabels())
			}

			req.Done <- buildSuccess
		} else {
			buildSuccess = false

			scopedLog.Debug("My request was cancelled because I'm already in line")
		}
		// The external listener can ignore the channel so we need to
		// make sure we don't block
		select {
		case req.ExternalDone <- buildSuccess:
		default:
		}
		close(req.ExternalDone)
	}(owner, newReq, e)
	return newReq.ExternalDone
}

// TriggerPolicyUpdatesLocked indicates that a policy change is likely to
// affect this endpoint. Will update all required endpoint configuration and
// state to reflect new policy.
//
// Returns true if policy was changed and the endpoint needs to be rebuilt
func (e *Endpoint) TriggerPolicyUpdatesLocked(owner Owner, opts models.ConfigurationMap) (bool, error) {

	if e.SecurityIdentity == nil {
		return false, nil
	}

	needToRegenerateBPF, err := e.regeneratePolicy(owner, opts)
	if err != nil {
		return false, fmt.Errorf("%s: %s", e.StringID(), err)
	}

	e.getLogger().Debugf("TriggerPolicyUpdatesLocked: changed: %t", needToRegenerateBPF)

	return needToRegenerateBPF, nil
}

func (e *Endpoint) runIdentityToK8sPodSync() {
	e.controllers.UpdateController(fmt.Sprintf("sync-identity-to-k8s-pod (%d)", e.ID),
		controller.ControllerParams{
			DoFunc: func() error {
				id := ""

				e.Mutex.RLock()
				if e.SecurityIdentity != nil {
					id = e.SecurityIdentity.ID.String()
				}
				e.Mutex.RUnlock()

				if id != "" && e.GetK8sNamespace() != "" && e.GetK8sPodName() != "" {
					return k8s.AnnotatePod(e, common.CiliumIdentityAnnotation, id)
				}

				return nil
			},
			RunInterval: 1 * time.Minute,
		},
	)
}

// FormatGlobalEndpointID returns the global ID of endpoint in the format
// / <global ID Prefix>:<cluster name>:<node name>:<endpoint ID> as a string.
func (e *Endpoint) FormatGlobalEndpointID() string {
	nodeIdentity, _ := node.GetLocalNode()
	metadata := []string{CiliumGlobalIdPrefix, ipcache.AddressSpace, nodeIdentity.Name, strconv.Itoa(int(e.ID))}
	return strings.Join(metadata, ":")
}

// This synchronizes the key-value store with a mapping of the endpoint's IP
// with the numerical ID representing its security identity.
func (e *Endpoint) runIPIdentitySync(endpointIP addressing.CiliumIP) {

	if endpointIP == nil {
		return
	}

	addressFamily := endpointIP.GetFamilyString()

	e.controllers.UpdateController(fmt.Sprintf("sync-%s-identity-mapping (%d)", addressFamily, e.ID),
		controller.ControllerParams{
			DoFunc: func() error {

				e.Mutex.RLock()

				if e.state == StateDisconnected || e.state == StateDisconnecting {
					log.WithFields(logrus.Fields{logfields.EndpointState: e.state}).
						Debugf("not synchronizing endpoint IP with kvstore due to endpoint state")
					e.Mutex.RUnlock()
					return nil
				}

				if e.SecurityIdentity == nil {
					e.Mutex.RUnlock()
					return nil
				}

				IP := endpointIP.IP()
				ID := e.SecurityIdentity.ID
				metadata := e.FormatGlobalEndpointID()

				// Release lock as we do not want to have long-lasting key-value
				// store operations resulting in lock being held for a long time.
				e.Mutex.RUnlock()

				if err := ipcache.UpsertIPToKVStore(IP, ID, metadata); err != nil {
					return fmt.Errorf("unable to add endpoint IP mapping '%s'->'%d': %s", IP.String(), ID, err)
				}
				return nil
			},
			StopFunc: func() error {
				ip := endpointIP.String()
				if err := ipcache.DeleteIPFromKVStore(ip); err != nil {
					return fmt.Errorf("unable to delete endpoint IP '%s' from ipcache: %s", ip, err)
				}
				return nil
			},
			RunInterval: 5 * time.Minute,
		},
	)
}

// SetIdentity resets endpoint's policy identity to 'id'.
// Caller triggers policy regeneration if needed.
// Called with e.Mutex Locked
func (e *Endpoint) SetIdentity(identity *identityPkg.Identity) {

	e.SecurityIdentity = identity

	// Sets endpoint state to ready if was waiting for identity
	if e.GetStateLocked() == StateWaitingForIdentity {
		e.SetStateLocked(StateReady, "Set identity for this endpoint")
	}

	e.runIdentityToK8sPodSync()

	// Whenever the identity is updated, propagate change to key-value store
	// of IP to identity mapping.
	e.runIPIdentitySync(e.IPv4)
	e.runIPIdentitySync(e.IPv6)

	e.getLogger().WithFields(logrus.Fields{
		logfields.Identity: identity,
	}).Debug("Set identity of endpoint")
}
