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
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
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

var (
	// localHostKey represents an ingress L3 allow from the local host.
	localHostKey = policymap.PolicyKey{
		Identity:         identityPkg.ReservedIdentityHost.Uint32(),
		TrafficDirection: policymap.Ingress.Uint8(),
	}

	// worldKey represents an ingress L3 allow from the world.
	worldKey = policymap.PolicyKey{
		Identity:         identityPkg.ReservedIdentityWorld.Uint32(),
		TrafficDirection: policymap.Ingress.Uint8(),
	}
)

// ProxyID returns a unique string to identify a proxy mapping.
func (e *Endpoint) ProxyID(l4 *policy.L4Filter) string {
	return policy.ProxyID(e.ID, l4.Ingress, string(l4.Protocol), uint16(l4.Port))
}

func getSecurityIdentities(labelsMap identityPkg.IdentityCache, selector *api.EndpointSelector) []identityPkg.NumericIdentity {
	identities := []identityPkg.NumericIdentity{}
	for idx, labels := range labelsMap {
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

// convertL4FilterToPolicyMapKeys converts filter into a list of PolicyKeys
// that apply to this endpoint.
// Must be called with endpoint.Mutex locked.
func (e *Endpoint) convertL4FilterToPolicyMapKeys(filter *policy.L4Filter, direction policymap.TrafficDirection) []policymap.PolicyKey {
	keysToAdd := []policymap.PolicyKey{}
	port := uint16(filter.Port)
	proto := uint8(filter.U8Proto)

	for _, sel := range filter.Endpoints {
		for _, id := range getSecurityIdentities(*e.LabelsMap, &sel) {
			srcID := id.Uint32()
			keyToAdd := policymap.PolicyKey{
				Identity: srcID,
				// NOTE: Port is in host byte-order!
				DestPort:         port,
				Nexthdr:          proto,
				TrafficDirection: direction.Uint8(),
			}
			keysToAdd = append(keysToAdd, keyToAdd)
		}
	}
	return keysToAdd
}

func (e *Endpoint) computeDesiredL4PolicyMapEntries(keysToAdd map[policymap.PolicyKey]struct{}) {
	if keysToAdd == nil {
		keysToAdd = map[policymap.PolicyKey]struct{}{}
	}

	if e.DesiredL4Policy == nil {
		return
	}

	for _, filter := range e.DesiredL4Policy.Ingress {
		keysFromFilter := e.convertL4FilterToPolicyMapKeys(&filter, policymap.Ingress)
		for _, keyFromFilter := range keysFromFilter {
			keysToAdd[keyFromFilter] = struct{}{}
		}
	}

	for _, filter := range e.DesiredL4Policy.Egress {
		keysFromFilter := e.convertL4FilterToPolicyMapKeys(&filter, policymap.Egress)
		for _, keyFromFilter := range keysFromFilter {
			keysToAdd[keyFromFilter] = struct{}{}
		}
	}
	return
}

func getLabelsMap() (*identityPkg.IdentityCache, error) {
	labelsMap := identityPkg.GetIdentityCache()

	reservedIDs := identityPkg.GetAllReservedIdentities()
	var idx identityPkg.NumericIdentity
	for _, idx = range reservedIDs {
		identity := identityPkg.LookupIdentityByID(idx)
		if identity == nil {
			return nil, fmt.Errorf("unable to resolve reserved identity")
		}
		lbls := identity.Labels.ToSlice()
		if len(lbls) == 0 {
			return nil, fmt.Errorf("unable to resolve reserved identity")
		}
		labelsMap[idx] = lbls
	}

	return &labelsMap, nil
}

// resolveL4Policy iterates through the policy repository to determine whether
// any L4 (including L4-dependent L7) policy changes have occurred. If an error
// occurs during calculation, it will return (false, err). Otherwise, it will
// determine whether there is a difference between the current realized state
// and the desired state, and return if there is a difference (true, nil) or
// not (false, nil).
//
// Must be called with global endpoint.Mutex held.
func (e *Endpoint) resolveL4Policy(repo *policy.Repository) (policyChanged bool, err error) {
	var newL4IngressPolicy, newL4EgressPolicy *policy.L4PolicyMap

	ingressCtx := policy.SearchContext{
		To: e.SecurityIdentity.LabelArray,
	}

	egressCtx := policy.SearchContext{
		From: e.SecurityIdentity.LabelArray,
	}

	if option.Config.TracingEnabled() {
		ingressCtx.Trace = policy.TRACE_ENABLED
		egressCtx.Trace = policy.TRACE_ENABLED
	}

	newL4IngressPolicy, err = repo.ResolveL4IngressPolicy(&ingressCtx)
	if err != nil {
		return
	}

	newL4EgressPolicy, err = repo.ResolveL4EgressPolicy(&egressCtx)
	if err != nil {
		return
	}

	newL4Policy := &policy.L4Policy{Ingress: *newL4IngressPolicy,
		Egress: *newL4EgressPolicy}

	if !reflect.DeepEqual(e.DesiredL4Policy, newL4Policy) {
		policyChanged = true
		e.DesiredL4Policy = newL4Policy
	}

	return
}

func (e *Endpoint) computeDesiredPolicyMapState(owner Owner, labelsMap *identityPkg.IdentityCache,
	repo *policy.Repository) {
	desiredPolicyKeys := make(map[policymap.PolicyKey]struct{})
	if e.LabelsMap != labelsMap {
		e.LabelsMap = labelsMap
	}
	e.computeDesiredL4PolicyMapEntries(desiredPolicyKeys)
	e.determineAllowLocalhost(desiredPolicyKeys)
	e.determineAllowFromWorld(desiredPolicyKeys)
	e.computeDesiredL3PolicyMapEntries(owner, labelsMap, repo, desiredPolicyKeys)
	e.desiredMapState = desiredPolicyKeys
}

// determineAllowLocalhost determines whether endpoint should be allowed to
// communicate with the localhost. It inserts the PolicyKey corresponding to
// the localhost in the desiredPolicyKeys if the endpoint is allowed to
// communicate with the localhost.
func (e *Endpoint) determineAllowLocalhost(desiredPolicyKeys map[policymap.PolicyKey]struct{}) {

	if desiredPolicyKeys == nil {
		desiredPolicyKeys = map[policymap.PolicyKey]struct{}{}
	}

	if option.Config.AlwaysAllowLocalhost() || (e.DesiredL4Policy != nil && e.DesiredL4Policy.HasRedirect()) {
		desiredPolicyKeys[localHostKey] = struct{}{}
	}
}

// determineAllowFromWorld determines whether world should be allowed to
// communicate with the endpoint, based on legacy Cilium 1.0 behaviour. It
// inserts the PolicyKey corresponding to the world in the desiredPolicyKeys
// if the legacy mode is enabled.
//
// This must be run after determineAllowLocalhost().
//
// For more information, see https://cilium.link/host-vs-world
func (e *Endpoint) determineAllowFromWorld(desiredPolicyKeys map[policymap.PolicyKey]struct{}) {

	if desiredPolicyKeys == nil {
		desiredPolicyKeys = map[policymap.PolicyKey]struct{}{}
	}

	_, localHostAllowed := desiredPolicyKeys[localHostKey]
	if option.Config.HostAllowsWorld && localHostAllowed {
		desiredPolicyKeys[worldKey] = struct{}{}
	}
}

func (e *Endpoint) computeDesiredL3PolicyMapEntries(owner Owner, identityCache *identityPkg.IdentityCache, repo *policy.Repository, desiredPolicyKeys map[policymap.PolicyKey]struct{}) {

	if desiredPolicyKeys == nil {
		desiredPolicyKeys = map[policymap.PolicyKey]struct{}{}
	}

	ingressCtx := policy.SearchContext{
		To: e.SecurityIdentity.LabelArray,
	}
	egressCtx := policy.SearchContext{
		From: e.SecurityIdentity.LabelArray,
	}

	if option.Config.TracingEnabled() {
		ingressCtx.Trace = policy.TRACE_ENABLED
		egressCtx.Trace = policy.TRACE_ENABLED
	}

	// Only L3 (label-based) policy apply.
	// Complexity increases linearly by the number of identities in the map.
	for identity, labels := range *identityCache {
		ingressCtx.From = labels
		egressCtx.To = labels

		var ingressAccess api.Decision
		if e.Opts.IsEnabled(option.IngressPolicy) {
			ingressAccess = repo.AllowsIngressLabelAccess(&ingressCtx)
		} else {
			// If policy enforcement is disabled, set the policy to an
			// allow-all policy. That policy will be set in the L4 policy map
			// until the BPF program is generated and installed, which will
			// then ignore the policy. That way, we won't drop traffic between
			// the BPF map update and the BPF program installation.
			ingressAccess = api.Allowed
		}
		if ingressAccess == api.Allowed {
			keyToAdd := policymap.PolicyKey{
				Identity:         identity.Uint32(),
				TrafficDirection: policymap.Ingress.Uint8(),
			}
			desiredPolicyKeys[keyToAdd] = struct{}{}
		}

		var egressAccess api.Decision
		if e.Opts.IsEnabled(option.EgressPolicy) {
			egressAccess = repo.AllowsEgressLabelAccess(&egressCtx)
		} else {
			// If policy enforcement is disabled, set the policy to an
			// allow-all policy. That policy will be set in the L4 policy map
			// until the BPF program is generated and installed, which will
			// then ignore the policy. That way, we won't drop traffic between
			// the BPF map update and the BPF program installation.
			egressAccess = api.Allowed
		}
		if egressAccess == api.Allowed {
			keyToAdd := policymap.PolicyKey{
				Identity:         identity.Uint32(),
				TrafficDirection: policymap.Egress.Uint8(),
			}
			desiredPolicyKeys[keyToAdd] = struct{}{}
		}
	}
}

// Must be called with global repo.Mutrex, e.Mutex, and c.Mutex held
func (e *Endpoint) regenerateL3Policy(repo *policy.Repository, revision uint64) (bool, error) {

	ctx := policy.SearchContext{
		To: e.SecurityIdentity.LabelArray, // keep c.Mutex taken to protect this.
	}
	if option.Config.TracingEnabled() {
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
	return policy.GetPolicyEnabled() == option.AlwaysEnforce ||
		e.Opts.IsEnabled(option.IngressPolicy) ||
		e.Opts.IsEnabled(option.EgressPolicy)
}

func (e *Endpoint) updateNetworkPolicy(owner Owner) error {
	// Skip updating the NetworkPolicy if no policy has been calculated.
	// This breaks a circular dependency between configuring NetworkPolicies in
	// sidecar Envoy proxies and those proxies needing network connectivity
	// to get their initial configuration, which is required for them to ACK
	// the NetworkPolicies.
	if !e.PolicyCalculated || e.SecurityIdentity == nil {
		return nil
	}

	// Compute the set of identities explicitly denied by policy.
	// This loop is similar to the one in computeDesiredPolicyMapState called
	// above, but this set only contains the identities with "Denied" verdicts.
	ctx := policy.SearchContext{
		To: e.SecurityIdentity.LabelArray,
	}
	if option.Config.TracingEnabled() {
		ctx.Trace = policy.TRACE_ENABLED
	}
	deniedIngressIdentities := make(map[identityPkg.NumericIdentity]bool)
	for srcID, srcLabels := range *e.LabelsMap {
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
		From: e.SecurityIdentity.LabelArray,
	}

	deniedEgressIdentities := make(map[identityPkg.NumericIdentity]bool)
	for dstID, dstLabels := range *e.LabelsMap {
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
	err := owner.UpdateNetworkPolicy(e, e.DesiredL4Policy, *e.LabelsMap, deniedIngressIdentities, deniedEgressIdentities)
	if err != nil {
		return err
	}

	return nil
}

// regeneratePolicy regenerates endpoint's policy if needed and returns
// whether the BPF for the given endpoint should be regenerated.
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

	e.getLogger().Debug("Starting regenerate...")

	// Collect label arrays before policy computation, as this can fail.
	// GH-1128 should allow optimizing this away, but currently we can't
	// reliably know if the KV-store has changed or not, so we must scan
	// through it each time.
	labelsMap, err := getLabelsMap()
	if err != nil {
		e.getLogger().WithError(err).Debug("Received error while evaluating policy")
		return false, err
	}
	// Use the old labelsMap instance if the new one is still the same.
	// Later we can compare the pointers to figure out if labels have changed or not.
	if reflect.DeepEqual(e.LabelsMap, labelsMap) {
		labelsMap = e.LabelsMap
	}

	repo := owner.GetPolicyRepository()
	repo.Mutex.RLock()
	revision := repo.GetRevision()
	defer repo.Mutex.RUnlock()

	// Recompute policy for this endpoint only if not already done for this revision.
	// Must recompute if labels have changed or option changes are requested.
	if !e.forcePolicyCompute && e.nextPolicyRevision >= revision &&
		labelsMap == e.LabelsMap && opts == nil {

		e.getLogger().WithFields(logrus.Fields{
			"policyRevision.next": e.nextPolicyRevision,
			"policyRevision.repo": revision,
			"policyChanged":       e.nextPolicyRevision > e.policyRevision,
		}).Debug("skipping policy recalculation")
		// This revision already computed, but may still need to be applied to BPF
		return e.nextPolicyRevision > e.policyRevision, nil
	}

	if opts == nil {
		opts = make(models.ConfigurationMap)
	}

	// Containers without a security identity are not accessible
	if e.SecurityIdentity == nil {
		e.getLogger().Warn("Endpoint lacks identity, skipping policy calculation")
		return false, nil
	}

	// Skip L4 policy recomputation if possible. However, the rest of the
	// policy computation still needs to be done for each endpoint separately.
	l4PolicyChanged := false
	if e.Iteration != revision {
		l4PolicyChanged, err = e.resolveL4Policy(repo)
		if err != nil {
			return false, err
		}
		// Result is valid until cache iteration advances
		e.Iteration = revision
	} else {
		e.getLogger().WithField(logfields.Identity, e.SecurityIdentity.ID).Debug("Reusing cached L4 policy")
	}

	// Calculate L3 (CIDR) policy.
	var l3PolicyChanged bool
	if l3PolicyChanged, err = e.regenerateL3Policy(repo, revision); err != nil {
		return false, err
	}
	if l3PolicyChanged {
		e.getLogger().Debug("regeneration of L3 (CIDR) policy caused policy change")
	}

	// no failures after this point

	// Apply possible option changes before regenerating maps, as map regeneration
	// depends on the conntrack options
	if e.DesiredL4Policy != nil {
		if e.DesiredL4Policy.RequiresConntrack() {
			opts[option.Conntrack] = optionEnabled
		}
	}

	ingress, egress := owner.EnableEndpointPolicyEnforcement(e)

	opts[option.IngressPolicy] = optionDisabled
	opts[option.EgressPolicy] = optionDisabled

	if !ingress && !egress {
		e.getLogger().Debug("ingress and egress policy enforcement not enabled")
	} else {
		if ingress && egress {
			e.getLogger().Debug("policy enforcement for ingress and egress enabled")
			opts[option.IngressPolicy] = optionEnabled
			opts[option.EgressPolicy] = optionEnabled
		} else if ingress {
			e.getLogger().Debug("policy enforcement for ingress enabled")
			opts[option.IngressPolicy] = optionEnabled
		} else {
			e.getLogger().Debug("policy enforcement for egress enabled")
			opts[option.EgressPolicy] = optionEnabled
		}
	}

	optsChanged := e.applyOptsLocked(opts)

	e.computeDesiredPolicyMapState(owner, labelsMap, repo)

	// If we are in this function, then policy has been calculated.
	if !e.PolicyCalculated {
		e.getLogger().Debug("setting PolicyCalculated to true for endpoint")
		e.PolicyCalculated = true
		// Always trigger a regenerate after the first policy
		// calculation has been performed
		optsChanged = true
	}

	if e.forcePolicyCompute {
		optsChanged = true           // Options were changed by the caller.
		e.forcePolicyCompute = false // Policies just computed
		e.getLogger().Debug("Forced policy recalculation")
	}

	e.nextPolicyRevision = revision

	if !owner.DryModeEnabled() {
		e.syncPolicyMapController()
	}

	// If no policy or options change occurred for this endpoint then the endpoint is
	// already running the latest revision, otherwise we have to wait for
	// the regeneration of the endpoint to complete.
	policyChanged := l3PolicyChanged || l4PolicyChanged

	e.getLogger().WithFields(logrus.Fields{
		"policyChanged":       policyChanged,
		"optsChanged":         optsChanged,
		"policyRevision.next": e.nextPolicyRevision,
	}).Debug("Done calculating policy")

	needToRegenerateBPF := optsChanged || policyChanged || e.nextPolicyRevision > e.policyRevision

	return needToRegenerateBPF, nil
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

	revision, compilationExecuted, err := e.regenerateBPF(owner, tmpDir, reason)

	// If generation fails, keep the directory around. If it ever succeeds
	// again, clean up the XXX_next_fail copy.
	failDir := e.failedDirectoryPath()
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

	// If the compilation was skipped then we need to copy the old bpf objects
	// into the new directory
	if !compilationExecuted {
		err := common.MoveNewFilesTo(backupDir, origDir)
		if err != nil {
			log.WithError(err).Debugf("Unable to copy old bpf object "+
				"files from %s into the new directory %s.", backupDir, origDir)
		}
	}

	os.RemoveAll(backupDir)

	// Update desired policy for endpoint because policy has now been realized
	// in the datapath. PolicyMap state is not updated here, because that is
	// performed in endpoint.syncPolicyMap().
	e.Mutex.Lock()
	e.RealizedL4Policy = e.DesiredL4Policy
	e.Mutex.Unlock()

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

			err := e.regenerate(owner, reason)
			repr, reprerr := monitor.EndpointRegenRepr(e, err)
			if reprerr != nil {
				scopedLog.WithError(reprerr).Warn("Notifying monitor about endpoint regeneration failed")
			}

			if err != nil {
				buildSuccess = false
				scopedLog.WithError(err).Warn("Regeneration of endpoint program failed")
				e.LogStatus(BPF, Failure, "Error regenerating endpoint: "+err.Error())
				if reprerr == nil {
					owner.SendNotification(monitor.AgentNotifyEndpointRegenerateFail, repr)
				}
			} else {
				buildSuccess = true
				e.LogStatusOK(BPF, "Successfully regenerated endpoint program due to "+reason)
				if reprerr == nil {
					owner.SendNotification(monitor.AgentNotifyEndpointRegenerateSuccess, repr)
				}
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
	// If it does not need datapath regeneration then we should set the policy
	// revision with nextPolicyRevision.
	if !needToRegenerateBPF {
		e.setPolicyRevision(e.nextPolicyRevision)
	}

	// CurrentStatus will be not OK when we have an uncleared error in BPF,
	// policy or Other. We should keep trying to regenerate in the hopes of
	// suceeding.
	// Note: This "retry" behaviour is better suited to a controller, and can be
	// moved there once we have an endpoint regeneration controller.
	needToRegenerateBPF = needToRegenerateBPF || (e.Status.CurrentStatus() != OK)

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
					return k8s.AnnotatePod(e, k8sConst.CiliumIdentityAnnotation, id)
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
	metadata := []string{endpointid.CiliumGlobalIdPrefix, ipcache.AddressSpace, nodeIdentity.Name, strconv.Itoa(int(e.ID))}
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

	// Set a boolean flag to indicate whether the endpoint has been injected by
	// Istio with a Cilium-compatible sidecar proxy.
	istioSidecarProxyLabel := identity.Labels[k8sConst.PolicyLabelIstioSidecarProxy]
	e.hasSidecarProxy = istioSidecarProxyLabel != nil &&
		istioSidecarProxyLabel.Source == labels.LabelSourceK8s &&
		strings.ToLower(istioSidecarProxyLabel.Value) == "true"

	oldIdentity := "no identity"
	if e.SecurityIdentity != nil {
		oldIdentity = e.SecurityIdentity.StringID()
	}

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
		logfields.Identity:       identity.StringID(),
		logfields.OldIdentity:    oldIdentity,
		logfields.IdentityLabels: identity.Labels.String(),
	}).Info("Identity of endpoint changed")
}
