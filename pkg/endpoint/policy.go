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
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/completion"
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

// RegenerationContext provides context to regenerate() calls to determine
// the caller, and which specific aspects to regeneration are necessary to
// update the datapath to implement the new behavior.
type RegenerationContext struct {
	// Reason provides context to source for the regeneration, which is
	// used to generate useful log messages.
	Reason string

	// ReloadDatapath forces the datapath programs to be reloaded. It does
	// not guarantee recompilation of the programs.
	ReloadDatapath bool
}

// NewRegenerationContext returns a new context for regeneration that does not
// force any recalculation, rebuild or reload of policy.
func NewRegenerationContext(reason string) *RegenerationContext {
	return &RegenerationContext{
		Reason: reason,
	}
}

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
		for _, id := range getSecurityIdentities(*e.prevIdentityCache, &sel) {
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

// lookupRedirectPort returns the redirect L4 proxy port for the given L4
// policy map key, in host byte order. Returns 0 if not found or the
// filter doesn't require a redirect.
// Must be called with Endpoint.Mutex held.
func (e *Endpoint) lookupRedirectPort(l4Filter *policy.L4Filter) uint16 {
	if !l4Filter.IsRedirect() {
		return 0
	}
	proxyID := e.ProxyID(l4Filter)
	return e.realizedRedirects[proxyID]
}

func (e *Endpoint) computeDesiredL4PolicyMapEntries(keysToAdd PolicyMapState) {
	if keysToAdd == nil {
		keysToAdd = PolicyMapState{}
	}

	if e.DesiredL4Policy == nil {
		return
	}

	for _, filter := range e.DesiredL4Policy.Ingress {
		keysFromFilter := e.convertL4FilterToPolicyMapKeys(&filter, policymap.Ingress)
		for _, keyFromFilter := range keysFromFilter {
			var proxyPort uint16
			// Preserve the already-allocated proxy ports for redirects that
			// already exist.
			if filter.IsRedirect() {
				proxyPort = e.lookupRedirectPort(&filter)
				// If the currently allocated proxy port is 0, this is a new
				// redirect, for which no port has been allocated yet. Ignore
				// it for now. This will be configured by
				// e.addNewRedirectsFromMap once the port has been allocated.
				if proxyPort == 0 {
					continue
				}
			}
			keysToAdd[keyFromFilter] = PolicyMapStateEntry{ProxyPort: proxyPort}
		}
	}

	for _, filter := range e.DesiredL4Policy.Egress {
		keysFromFilter := e.convertL4FilterToPolicyMapKeys(&filter, policymap.Egress)
		for _, keyFromFilter := range keysFromFilter {
			var proxyPort uint16
			// Preserve the already-allocated proxy ports for redirects that
			// already exist.
			if filter.IsRedirect() {
				proxyPort = e.lookupRedirectPort(&filter)
				// If the currently allocated proxy port is 0, this is a new
				// redirect, for which no port has been allocated yet. Ignore
				// it for now. This will be configured by
				// e.addNewRedirectsFromMap once the port has been allocated.
				if proxyPort == 0 {
					continue
				}
			}
			keysToAdd[keyFromFilter] = PolicyMapStateEntry{ProxyPort: proxyPort}
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

func (e *Endpoint) computeDesiredPolicyMapState(repo *policy.Repository) {
	desiredPolicyKeys := make(PolicyMapState)
	e.computeDesiredL4PolicyMapEntries(desiredPolicyKeys)
	e.determineAllowLocalhost(desiredPolicyKeys)
	e.determineAllowFromWorld(desiredPolicyKeys)
	e.computeDesiredL3PolicyMapEntries(repo, desiredPolicyKeys)
	e.desiredMapState = desiredPolicyKeys
}

// determineAllowLocalhost determines whether endpoint should be allowed to
// communicate with the localhost. It inserts the PolicyKey corresponding to
// the localhost in the desiredPolicyKeys if the endpoint is allowed to
// communicate with the localhost.
func (e *Endpoint) determineAllowLocalhost(desiredPolicyKeys PolicyMapState) {

	if desiredPolicyKeys == nil {
		desiredPolicyKeys = PolicyMapState{}
	}

	if option.Config.AlwaysAllowLocalhost() || (e.DesiredL4Policy != nil && e.DesiredL4Policy.HasRedirect()) {
		desiredPolicyKeys[localHostKey] = PolicyMapStateEntry{}
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
func (e *Endpoint) determineAllowFromWorld(desiredPolicyKeys PolicyMapState) {

	if desiredPolicyKeys == nil {
		desiredPolicyKeys = PolicyMapState{}
	}

	_, localHostAllowed := desiredPolicyKeys[localHostKey]
	if option.Config.HostAllowsWorld && localHostAllowed {
		desiredPolicyKeys[worldKey] = PolicyMapStateEntry{}
	}
}

func (e *Endpoint) computeDesiredL3PolicyMapEntries(repo *policy.Repository, desiredPolicyKeys PolicyMapState) {

	if desiredPolicyKeys == nil {
		desiredPolicyKeys = PolicyMapState{}
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

	ingressPolicyEnabled := e.ingressPolicyEnabled
	egressPolicyEnabled := e.egressPolicyEnabled

	// Only L3 (label-based) policy apply.
	// Complexity increases linearly by the number of identities in the map.
	for identity, labels := range *e.prevIdentityCache {
		ingressCtx.From = labels
		egressCtx.To = labels

		var ingressAccess api.Decision
		if ingressPolicyEnabled {
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
			desiredPolicyKeys[keyToAdd] = PolicyMapStateEntry{}
		}

		var egressAccess api.Decision
		if egressPolicyEnabled {
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
			desiredPolicyKeys[keyToAdd] = PolicyMapStateEntry{}
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

// must be called with endpoint.Mutex held for reading
func (e *Endpoint) updateNetworkPolicy(owner Owner, proxyWaitGroup *completion.WaitGroup) error {
	// Skip updating the NetworkPolicy if no policy has been calculated.
	// This breaks a circular dependency between configuring NetworkPolicies in
	// sidecar Envoy proxies and those proxies needing network connectivity
	// to get their initial configuration, which is required for them to ACK
	// the NetworkPolicies.
	if !e.policyCalculated || e.SecurityIdentity == nil {
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
	for srcID, srcLabels := range *e.prevIdentityCache {
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
	for dstID, dstLabels := range *e.prevIdentityCache {
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
	err := owner.UpdateNetworkPolicy(e, e.DesiredL4Policy, *e.prevIdentityCache, deniedIngressIdentities, deniedEgressIdentities, proxyWaitGroup)
	if err != nil {
		return err
	}

	return nil
}

// regeneratePolicy regenerates endpoint's policy if needed and returns whether
// the policy for the endpoint changed.
//
// Policy generation may fail, and in that case we exit before actually changing
// the policy in any way, so that the last policy remains fully in effect if the
// new policy can not be implemented. This is done on a per endpoint-basis,
// however, and it is possible that policy update succeeds for some endpoints,
// while it fails for other endpoints.
//
// Returns:
//  - isPolicyComp: true if the policy was changed for this endpoint;
//  - err: any error in obtaining information for computing policy, or if
// policy could not be generated given the current set of rules in the
// repository.
// Must be called with endpoint mutex held.
func (e *Endpoint) regeneratePolicy(owner Owner) (isPolicyComp bool, err error) {
	var labelsMap *identityPkg.IdentityCache
	var forceRegeneration bool

	e.getLogger().Debug("Starting regenerate...")

	// Collect label arrays before policy computation, as this can fail.
	// GH-1128 should allow optimizing this away, but currently we can't
	// reliably know if the KV-store has changed or not, so we must scan
	// through it each time.
	labelsMap, err = getLabelsMap()
	if err != nil {
		e.getLogger().WithError(err).Debug("Received error while evaluating policy")
		return false, err
	}

	regenerateStart := time.Now()
	// Capture successful regeneration time
	defer func() {
		if err == nil && isPolicyComp {
			regenerateTimeNs := time.Since(regenerateStart)
			regenerateTimeSec := float64(regenerateTimeNs) / float64(time.Second)
			e.getLogger().WithField(logfields.PolicyRegenerationTime, time.Since(regenerateStart).String()).
				Info("Regeneration of policy has completed")
			metrics.PolicyRegenerationCount.Inc()
			metrics.PolicyRegenerationTime.Add(regenerateTimeSec)
			metrics.PolicyRegenerationTimeSquare.Add(math.Pow(regenerateTimeSec, 2))
		}
	}()

	// Use the old labelsMap instance if the new one is still the same.
	// Later we can compare the pointers to figure out if labels have changed or not.
	if reflect.DeepEqual(e.prevIdentityCache, labelsMap) {
		labelsMap = e.prevIdentityCache
	}

	// Containers without a security identity are not accessible
	if e.SecurityIdentity == nil {
		e.getLogger().Warn("Endpoint lacks identity, skipping policy calculation")
		return false, nil
	}

	repo := owner.GetPolicyRepository()
	repo.Mutex.RLock()
	revision := repo.GetRevision()
	defer repo.Mutex.RUnlock()

	// Recompute policy for this endpoint only if not already done for this revision.
	// Must recompute if labels have changed or option changes are requested.
	if !e.forcePolicyCompute && e.nextPolicyRevision >= revision &&
		labelsMap == e.prevIdentityCache {

		e.getLogger().WithFields(logrus.Fields{
			"policyRevision.next": e.nextPolicyRevision,
			"policyRevision.repo": revision,
			"policyChanged":       e.nextPolicyRevision > e.policyRevision,
		}).Debug("skipping policy recalculation")
		// This revision already computed, but may still need to be applied to BPF
		return e.nextPolicyRevision > e.policyRevision, nil
	}

	e.prevIdentityCache = labelsMap

	// First step when calculating policy is to check whether ingress or egress
	// policy applies (i.e., if rules select this endpoint). We can use this
	// information to short-circuit policy generation if enforcement is
	// disabled for ingress and / or egress.
	e.ingressPolicyEnabled, e.egressPolicyEnabled = owner.EnableEndpointPolicyEnforcement(e)

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

	e.computeDesiredPolicyMapState(repo)

	// If we are in this function, then policy has been calculated.
	if !e.policyCalculated {
		e.getLogger().Debug("setting PolicyCalculated to true for endpoint")
		e.policyCalculated = true
		// Always trigger a regenerate after the first policy
		// calculation has been performed
		forceRegeneration = true
	}

	if e.forcePolicyCompute {
		forceRegeneration = true     // Options were changed by the caller.
		e.forcePolicyCompute = false // Policies just computed
		e.getLogger().Debug("Forced policy recalculation")
	}

	// Set the revision of this endpoint to the current revision of the policy
	// repository.
	e.nextPolicyRevision = revision

	// If no policy or options change occurred for this endpoint then the endpoint is
	// already running the latest revision, otherwise we have to wait for
	// the regeneration of the endpoint to complete.
	policyChanged := l3PolicyChanged || l4PolicyChanged

	e.getLogger().WithFields(logrus.Fields{
		"policyChanged":       policyChanged,
		"policyRevision.next": e.nextPolicyRevision,
		"forcedRegeneration":  forceRegeneration,
	}).Debug("Done calculating policy")

	// If the policy changed, or the revision of the policy repository has changed
	// we return true. It is possible that the endpoint's next policy revision
	// is the same as the endpoint's current policy revision; this indicates
	// that no new rules have been added in the policy repository; if policy
	// hasn't changed, and no new rules were added, and we haven't forced
	// regeneration for the endpoint, then return false.
	policyChanged = policyChanged || e.nextPolicyRevision > e.policyRevision || forceRegeneration

	return policyChanged, nil
}

// updateAndOverrideEndpointOptions updates the boolean configuration options for the endpoint
// based off of policy configuration, daemon policy enforcement mode, and any
// configuration options provided in opts. Returns whether the options changed
// from prior endpoint configuration. Note that the policy which applies
// to the endpoint, as well as the daemon's policy enforcement, may override
// configuration changes which were made via the API that were provided in opts.
// Must be called with endpoint mutex held.
func (e *Endpoint) updateAndOverrideEndpointOptions(owner Owner, opts option.OptionMap) (optsChanged bool) {
	if opts == nil {
		opts = make(option.OptionMap)
	}
	// Apply possible option changes before regenerating maps, as map regeneration
	// depends on the conntrack options
	if e.DesiredL4Policy != nil {
		if e.DesiredL4Policy.RequiresConntrack() {
			opts[option.Conntrack] = option.OptionEnabled
		}
	}

	optsChanged = e.applyOptsLocked(opts)
	return
}

// Called with e.Mutex UNlocked
func (e *Endpoint) regenerate(owner Owner, context *RegenerationContext) (retErr error) {
	var revision uint64
	var compilationExecuted bool
	var err error

	metrics.EndpointCountRegenerating.Inc()
	regenerateStart := time.Now()
	defer func() {
		metrics.EndpointCountRegenerating.Dec()
		if retErr == nil {
			metrics.EndpointRegenerationCount.
				WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()

			// Capture successful endpoint generation time
			regenerateTimeNs := time.Since(regenerateStart)
			regenerateTimeSec := float64(regenerateTimeNs) / float64(time.Second)
			e.getLogger().WithField(logfields.EndpointRegenerationTime, time.Since(regenerateStart).String()).Info("Regeneration of endpoint has completed")
			metrics.EndpointRegenerationTime.Add(regenerateTimeSec)
			metrics.EndpointRegenerationTimeSquare.Add(math.Pow(regenerateTimeSec, 2))
		} else {
			metrics.EndpointRegenerationCount.
				WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
		}
	}()

	e.BuildMutex.Lock()
	defer e.BuildMutex.Unlock()

	// Check if endpoints is still alive before doing any build
	if err = e.LockAlive(); err != nil {
		return err
	}

	// When building the initial drop policy in waiting-for-identity state
	// the state remains unchanged
	//
	// GH-5350: Remove this special case to require checking for StateWaitingForIdentity
	if e.GetStateLocked() != StateWaitingForIdentity &&
		!e.BuilderSetStateLocked(StateRegenerating, "Regenerating endpoint: "+context.Reason) {
		e.getLogger().WithField(logfields.EndpointState, e.state).Debug("Skipping build due to invalid state")
		e.Unlock()

		return fmt.Errorf("Skipping build due to invalid state: %s", e.state)
	}

	e.Unlock()

	scopedLog := e.getLogger()
	scopedLog.Debug("Regenerating endpoint...")

	origDir := filepath.Join(owner.GetStateDir(), e.StringID())

	// This is the temporary directory to store the generated headers,
	// the original existing directory is not overwritten until the
	// entire generation process has succeeded.
	tmpDir := getTempEndpointDirectory(origDir)

	// Create temporary endpoint directory if it does not exist yet
	if err := os.MkdirAll(tmpDir, 0777); err != nil {
		return fmt.Errorf("Failed to create endpoint directory: %s", err)
	}

	defer func() {
		if err := e.LockAlive(); err != nil {
			if retErr == nil {
				retErr = err
			} else {
				e.LogDisconnectedMutexAction(err, "after regenerate")
			}
			return
		}
		// Set to Ready, but only if no other changes are pending.
		// State will remain as waiting-to-regenerate if further
		// changes are needed. There should be an another regenerate
		// queued for taking care of it.
		e.BuilderSetStateLocked(StateReady, "Completed endpoint regeneration with no pending regeneration requests")
		e.Unlock()
	}()

	revision, compilationExecuted, err = e.regenerateBPF(owner, tmpDir, context)

	// Depending upon result of BPF regeneration (compilation executed, or
	// error occurred), shift endpoint directories to match said BPF regeneration
	// results.
	err = e.synchronizeDirectories(origDir, compilationExecuted, err)
	if err != nil {
		return fmt.Errorf("error synchronizing endpoint BPF program directories: %s", err)
	}

	// Update desired policy for endpoint because policy has now been realized
	// in the datapath. PolicyMap state is not updated here, because that is
	// performed in endpoint.syncPolicyMap().
	if err = e.LockAlive(); err != nil {
		return err
	}

	// Keep PolicyMap for this endpoint in sync with desired / realized state.
	if !owner.DryModeEnabled() {
		e.syncPolicyMapController()
	}

	e.RealizedL4Policy = e.DesiredL4Policy
	// Mark the endpoint to be running the policy revision it was
	// compiled for
	e.bumpPolicyRevisionLocked(revision)
	e.Unlock()

	scopedLog.Info("Endpoint policy recalculated")

	return nil
}

// Regenerate forces the regeneration of endpoint programs & policy
// Should only be called with e.state == StateWaitingToRegenerate or with
// e.state == StateWaitingForIdentity
func (e *Endpoint) Regenerate(owner Owner, context *RegenerationContext) <-chan bool {
	newReq := &Request{
		ID:           uint64(e.ID),
		MyTurn:       make(chan bool),
		Done:         make(chan bool),
		ExternalDone: make(chan bool),
	}

	go func(owner Owner, req *Request, e *Endpoint) {
		var buildSuccess bool

		err := e.RLockAlive()
		if err != nil {
			e.LogDisconnectedMutexAction(err, "before regeneration")
			req.ExternalDone <- false
			close(req.ExternalDone)
			return
		}
		e.RUnlock()
		scopedLog := e.getLogger()

		// We should only queue the request after we use all the endpoint's
		// lock/unlock. Otherwise this can get a deadlock if the endpoint is
		// being deleted at the same time. More info PR-1777.
		owner.QueueEndpointBuild(req)

		isMyTurn, isMyTurnChanOK := <-req.MyTurn
		if isMyTurnChanOK && isMyTurn {
			scopedLog.Debug("Dequeued endpoint from build queue")

			err := e.regenerate(owner, context)
			repr, reprerr := monitor.EndpointRegenRepr(e, err)
			if reprerr != nil {
				scopedLog.WithError(reprerr).Warn("Notifying monitor about endpoint regeneration failed")
			}

			if err != nil {
				buildSuccess = false
				scopedLog.WithError(err).Warn("Regeneration of endpoint program failed")
				e.LogStatus(BPF, Failure, "Error regenerating endpoint: "+err.Error())
				if reprerr == nil && !owner.DryModeEnabled() {
					owner.SendNotification(monitor.AgentNotifyEndpointRegenerateFail, repr)
				}
			} else {
				buildSuccess = true
				e.LogStatusOK(BPF, "Successfully regenerated endpoint program due to "+context.Reason)
				if reprerr == nil && !owner.DryModeEnabled() {
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
func (e *Endpoint) TriggerPolicyUpdatesLocked(owner Owner, opts option.OptionMap) (bool, error) {

	if e.SecurityIdentity == nil {
		return false, nil
	}

	policyChanged, err := e.regeneratePolicy(owner)
	if err != nil {
		return false, fmt.Errorf("%s: %s", e.StringID(), err)
	}

	optionsChanged := e.updateAndOverrideEndpointOptions(owner, opts)
	needToRegenerateBPF := optionsChanged || policyChanged

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

				if err := e.RLockAlive(); err != nil {
					return err
				}
				if e.SecurityIdentity != nil {
					id = e.SecurityIdentity.ID.StringID()
				}
				e.RUnlock()

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
	n := node.GetLocalNode()
	metadata := []string{endpointid.CiliumGlobalIdPrefix, ipcache.AddressSpace, n.Name, strconv.Itoa(int(e.ID))}
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

				// NOTE: this Lock is Unconditional because this controller
				// handles disconnecting endpoint state properly
				e.UnconditionalRLock()

				if e.state == StateDisconnected || e.state == StateDisconnecting {
					log.WithFields(logrus.Fields{logfields.EndpointState: e.state}).
						Debugf("not synchronizing endpoint IP with kvstore due to endpoint state")
					e.RUnlock()
					return nil
				}

				if e.SecurityIdentity == nil {
					e.RUnlock()
					return nil
				}

				IP := endpointIP.IP()
				ID := e.SecurityIdentity.ID
				hostIP := node.GetExternalIPv4()
				metadata := e.FormatGlobalEndpointID()

				// Release lock as we do not want to have long-lasting key-value
				// store operations resulting in lock being held for a long time.
				e.RUnlock()

				if err := ipcache.UpsertIPToKVStore(IP, hostIP, ID, metadata); err != nil {
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
