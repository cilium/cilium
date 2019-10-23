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

package endpoint

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/controller"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/ipcache"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/revert"

	"github.com/sirupsen/logrus"
)

// ProxyID returns a unique string to identify a proxy mapping.
func (e *Endpoint) ProxyID(l4 *policy.L4Filter) string {
	return policy.ProxyIDFromFilter(e.ID, l4)
}

// lookupRedirectPort returns the redirect L4 proxy port for the given L4
// policy map key, in host byte order. Returns 0 if not found or the
// filter doesn't require a redirect.
// Must be called with Endpoint.Mutex held.
func (e *Endpoint) LookupRedirectPort(l4Filter *policy.L4Filter) uint16 {
	if !l4Filter.IsRedirect() {
		return 0
	}
	proxyID := e.ProxyID(l4Filter)
	return e.realizedRedirects[proxyID]
}

// Note that this function assumes that endpoint policy has already been generated!
// must be called with endpoint.Mutex held for reading
func (e *Endpoint) updateNetworkPolicy(proxyWaitGroup *completion.WaitGroup) (reterr error, revertFunc revert.RevertFunc) {
	// Skip updating the NetworkPolicy if no identity has been computed for this
	// endpoint.
	// This breaks a circular dependency between configuring NetworkPolicies in
	// sidecar Envoy proxies and those proxies needing network connectivity
	// to get their initial configuration, which is required for them to ACK
	// the NetworkPolicies.
	if e.SecurityIdentity == nil {
		return nil, nil
	}

	// If desired L4Policy is nil then no policy change is needed.
	if e.desiredPolicy == nil || e.desiredPolicy.L4Policy == nil {
		return nil, nil
	}

	if e.isProxyDisabled() {
		return fmt.Errorf("can't update network policy, proxy disabled"), nil
	}

	// Publish the updated policy to L7 proxies.
	return e.proxy.UpdateNetworkPolicy(e, e.desiredPolicy.L4Policy, e.desiredPolicy.IngressPolicyEnabled, e.desiredPolicy.EgressPolicyEnabled, proxyWaitGroup)
}

func (e *Endpoint) useCurrentNetworkPolicy(proxyWaitGroup *completion.WaitGroup) {
	if e.SecurityIdentity == nil {
		return
	}

	// If desired L4Policy is nil then no policy change is needed.
	if e.desiredPolicy == nil || e.desiredPolicy.L4Policy == nil {
		return
	}

	if e.proxy != nil {
		// Wait for the current network policy to be acked
		e.proxy.UseCurrentNetworkPolicy(e, e.desiredPolicy.L4Policy, proxyWaitGroup)
	}
}

// setNextPolicyRevision updates the desired policy revision field
// Must be called with the endpoint lock held for at least reading
func (e *Endpoint) setNextPolicyRevision(revision uint64) {
	e.nextPolicyRevision = revision
	e.UpdateLogger(map[string]interface{}{
		logfields.DesiredPolicyRevision: e.nextPolicyRevision,
	})
}

// regeneratePolicy computes the policy for the given endpoint based off of the
// rules in regeneration.Owner's policy repository.
//
// Policy generation may fail, and in that case we exit before actually changing
// the policy in any way, so that the last policy remains fully in effect if the
// new policy can not be implemented. This is done on a per endpoint-basis,
// however, and it is possible that policy update succeeds for some endpoints,
// while it fails for other endpoints.
//
// Returns:
//  - err: any error in obtaining information for computing policy, or if
// policy could not be generated given the current set of rules in the
// repository.
// Must be called with endpoint mutex held.
func (e *Endpoint) regeneratePolicy() (retErr error) {
	var forceRegeneration bool

	// No point in calculating policy if endpoint does not have an identity yet.
	if e.SecurityIdentity == nil {
		e.getLogger().Warn("Endpoint lacks identity, skipping policy calculation")
		return nil
	}

	e.getLogger().Debug("Starting policy recalculation...")
	stats := &policyRegenerationStatistics{}
	stats.totalTime.Start()

	stats.waitingForPolicyRepository.Start()
	repo := e.owner.GetPolicyRepository()
	repo.Mutex.RLock()
	revision := repo.GetRevision()
	defer repo.Mutex.RUnlock()
	stats.waitingForPolicyRepository.End(true)

	// Recompute policy for this endpoint only if not already done for this revision.
	if !e.forcePolicyCompute && e.nextPolicyRevision >= revision {
		e.getLogger().WithFields(logrus.Fields{
			"policyRevision.next": e.nextPolicyRevision,
			"policyRevision.repo": revision,
			"policyChanged":       e.nextPolicyRevision > e.policyRevision,
		}).Debug("Skipping unnecessary endpoint policy recalculation")

		return nil
	}

	stats.policyCalculation.Start()
	if e.selectorPolicy == nil {
		// Upon initial insertion or restore, there's currently no good
		// trigger point to ensure that the security Identity is
		// assigned after the endpoint is added to the endpointmanager
		// (and hence also the identitymanager). In that case, detect
		// that the selectorPolicy is not set and find it.
		e.selectorPolicy = repo.GetPolicyCache().Lookup(e.SecurityIdentity)
		if e.selectorPolicy == nil {
			err := fmt.Errorf("no cached selectorPolicy found")
			e.getLogger().WithError(err).Warning("Failed to regenerate from cached policy")
			return err
		}
	}
	// TODO: GH-7515: This should be triggered closer to policy change
	// handlers, but for now let's just update it here.
	if err := repo.GetPolicyCache().UpdatePolicy(e.SecurityIdentity); err != nil {
		e.getLogger().WithError(err).Warning("Failed to update policy")
		return err
	}
	calculatedPolicy := e.selectorPolicy.Consume(e)
	stats.policyCalculation.End(true)

	// This marks the e.desiredPolicy different from the previously realized policy
	e.desiredPolicy = calculatedPolicy

	if e.forcePolicyCompute {
		forceRegeneration = true     // Options were changed by the caller.
		e.forcePolicyCompute = false // Policies just computed
		e.getLogger().Debug("Forced policy recalculation")
	}

	// Set the revision of this endpoint to the current revision of the policy
	// repository.
	e.setNextPolicyRevision(revision)

	e.updatePolicyRegenerationStatistics(stats, forceRegeneration, retErr)

	return nil
}

func (e *Endpoint) updatePolicyRegenerationStatistics(stats *policyRegenerationStatistics, forceRegeneration bool, err error) {
	success := err == nil

	stats.totalTime.End(success)
	stats.success = success

	stats.SendMetrics()

	fields := logrus.Fields{
		"waitingForIdentityCache":    stats.waitingForIdentityCache,
		"waitingForPolicyRepository": stats.waitingForPolicyRepository,
		"policyCalculation":          stats.policyCalculation,
		"forcedRegeneration":         forceRegeneration,
	}
	scopedLog := e.getLogger().WithFields(fields)

	if err != nil {
		scopedLog.WithError(err).Warn("Regeneration of policy failed")
		return
	}

	scopedLog.Debug("Completed endpoint policy recalculation")
}

// updateAndOverrideEndpointOptions updates the boolean configuration options for the endpoint
// based off of policy configuration, daemon policy enforcement mode, and any
// configuration options provided in opts. Returns whether the options changed
// from prior endpoint configuration. Note that the policy which applies
// to the endpoint, as well as the daemon's policy enforcement, may override
// configuration changes which were made via the API that were provided in opts.
// Must be called with endpoint mutex held.
func (e *Endpoint) updateAndOverrideEndpointOptions(opts option.OptionMap) (optsChanged bool) {
	if opts == nil {
		opts = make(option.OptionMap)
	}
	// Apply possible option changes before regenerating maps, as map regeneration
	// depends on the conntrack options
	if e.desiredPolicy != nil && e.desiredPolicy.L4Policy != nil {
		if e.desiredPolicy.L4Policy.RequiresConntrack() {
			opts[option.Conntrack] = option.OptionEnabled
		}
	}

	optsChanged = e.applyOptsLocked(opts)
	return
}

// updateRealizedState sets any realized state fields within the endpoint to
// be the desired state of the endpoint. This is only called after a successful
// regeneration of the endpoint.
func (e *Endpoint) updateRealizedState(stats *regenerationStatistics, origDir string, revision uint64, compilationExecuted bool) error {
	// Update desired policy for endpoint because policy has now been realized
	// in the datapath. PolicyMap state is not updated here, because that is
	// performed in endpoint.syncPolicyMap().
	stats.waitingForLock.Start()
	err := e.lockAlive()
	stats.waitingForLock.End(err == nil)
	if err != nil {
		return err
	}

	defer e.unlock()

	// Depending upon result of BPF regeneration (compilation executed),
	// shift endpoint directories to match said BPF regeneration
	// results.
	err = e.synchronizeDirectories(origDir, compilationExecuted)
	if err != nil {
		return fmt.Errorf("error synchronizing endpoint BPF program directories: %s", err)
	}

	// Keep PolicyMap for this endpoint in sync with desired / realized state.
	if !option.Config.DryMode {
		e.syncPolicyMapController()
	}

	// Set realized state to desired state.
	e.realizedPolicy = e.desiredPolicy

	// Mark the endpoint to be running the policy revision it was
	// compiled for
	e.setPolicyRevision(revision)

	return nil
}

// FormatGlobalEndpointID returns the global ID of endpoint in the format
// / <global ID Prefix>:<cluster name>:<node name>:<endpoint ID> as a string.
func (e *Endpoint) FormatGlobalEndpointID() string {
	localNodeName := node.GetName()
	metadata := []string{endpointid.CiliumGlobalIdPrefix.String(), ipcache.AddressSpace, localNodeName, strconv.Itoa(int(e.ID))}
	return strings.Join(metadata, ":")
}

// This synchronizes the key-value store with a mapping of the endpoint's IP
// with the numerical ID representing its security identity.
func (e *Endpoint) runIPIdentitySync(endpointIP addressing.CiliumIP) {

	if !endpointIP.IsSet() {
		return
	}

	addressFamily := endpointIP.GetFamilyString()

	e.controllers.UpdateController(fmt.Sprintf("sync-%s-identity-mapping (%d)", addressFamily, e.ID),
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				if err := e.rlockAlive(); err != nil {
					return controller.NewExitReason("Endpoint disappeared")
				}

				if e.SecurityIdentity == nil {
					e.runlock()
					return nil
				}

				IP := endpointIP.IP()
				ID := e.SecurityIdentity.ID
				hostIP := node.GetExternalIPv4()
				key := node.GetIPsecKeyIdentity()
				metadata := e.FormatGlobalEndpointID()
				k8sNamespace := e.K8sNamespace
				k8sPodName := e.K8sPodName

				// Release lock as we do not want to have long-lasting key-value
				// store operations resulting in lock being held for a long time.
				e.runlock()

				if err := ipcache.UpsertIPToKVStore(ctx, IP, hostIP, ID, key, metadata, k8sNamespace, k8sPodName); err != nil {
					return fmt.Errorf("unable to add endpoint IP mapping '%s'->'%d': %s", IP.String(), ID, err)
				}
				return nil
			},
			StopFunc: func(ctx context.Context) error {
				ip := endpointIP.String()
				if err := ipcache.DeleteIPFromKVStore(ctx, ip); err != nil {
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
func (e *Endpoint) SetIdentity(identity *identityPkg.Identity, newEndpoint bool) {

	// Set a boolean flag to indicate whether the endpoint has been injected by
	// Istio with a Cilium-compatible sidecar proxy.
	istioSidecarProxyLabel, found := identity.Labels[k8sConst.PolicyLabelIstioSidecarProxy]
	e.hasSidecarProxy = found &&
		istioSidecarProxyLabel.Source == labels.LabelSourceK8s &&
		strings.ToLower(istioSidecarProxyLabel.Value) == "true"

	oldIdentity := "no identity"
	if e.SecurityIdentity != nil {
		oldIdentity = e.SecurityIdentity.StringID()
	}

	// Current security identity for endpoint is its old identity - delete its
	// reference from global identity manager, add add a reference to the new
	// identity for the endpoint.
	if newEndpoint {
		// TODO - GH-9354.
		identitymanager.Add(identity)
	} else {
		identitymanager.RemoveOldAddNew(e.SecurityIdentity, identity)
	}
	e.SecurityIdentity = identity
	e.replaceIdentityLabels(identity.Labels)

	// Clear selectorPolicy. It will be determined at next regeneration.
	e.selectorPolicy = nil

	// Sets endpoint state to ready if was waiting for identity
	if e.getState() == StateWaitingForIdentity {
		e.setState(StateReady, "Set identity for this endpoint")
	}

	// Whenever the identity is updated, propagate change to key-value store
	// of IP to identity mapping.
	e.runIPIdentitySync(e.IPv4)
	e.runIPIdentitySync(e.IPv6)

	if oldIdentity != identity.StringID() {
		e.getLogger().WithFields(logrus.Fields{
			logfields.Identity:       identity.StringID(),
			logfields.OldIdentity:    oldIdentity,
			logfields.IdentityLabels: identity.Labels.String(),
		}).Info("Identity of endpoint changed")
	}
	e.UpdateLogger(map[string]interface{}{
		logfields.Identity: identity.StringID(),
	})
}

// GetCIDRPrefixLengths returns the sorted list of unique prefix lengths used
// for CIDR policy or IPcache lookup from this endpoint.
func (e *Endpoint) GetCIDRPrefixLengths() (s6, s4 []int) {
	if e.desiredPolicy == nil || e.desiredPolicy.CIDRPolicy == nil {
		return policy.GetDefaultPrefixLengths()
	}
	return e.desiredPolicy.CIDRPolicy.ToBPFData()
}

// UpdateVisibilityPolicy updates the visibility policy of this endpoint to
// reflect the state stored in the provided proxy visibility annotation. If anno
// is empty, then the VisibilityPolicy for the Endpoint will be empty, and will
// have no effect. If the proxy visibility annotation cannot be parsed, an empty
// visibility policy is assigned to the Endpoint.
func (e *Endpoint) UpdateVisibilityPolicy(anno string) {
	if err := e.lockAlive(); err != nil {
		// If the endpoint is being deleted, we don't need to update its
		// visibility policy.
		return
	}

	defer func() {
		// Ensure that policy computation is performed so that endpoint
		// desiredPolicy and realizedPolicy pointers are different. This state
		// is needed to update endpoint policy maps with the policy map state
		// generated from the visibility policy. This can, and should be more
		// elegant in the future.
		e.forcePolicyComputation()
		e.unlock()
	}()

	var (
		nvp *policy.VisibilityPolicy
		err error
	)

	if anno != "" {
		e.getLogger().Debug("creating visibility policy")
		nvp, err = policy.NewVisibilityPolicy(anno)
		if err != nil {
			e.getLogger().WithError(err).Warning("unable to parse annotations into visibility policy; disabling visibility policy for endpoint")
			e.visibilityPolicy = &policy.VisibilityPolicy{
				Ingress: make(policy.DirectionalVisibilityPolicy),
				Egress:  make(policy.DirectionalVisibilityPolicy),
			}
			return
		}
	}

	e.visibilityPolicy = nvp
	return
}

// SetPolicyRevision sets the endpoint's policy revision with the given
// revision.
func (e *Endpoint) SetPolicyRevision(rev uint64) {
	if err := e.lockAlive(); err != nil {
		return
	}
	e.setPolicyRevision(rev)
	e.unlock()
}

// setPolicyRevision sets the endpoint's policy revision with the given
// revision.
func (e *Endpoint) setPolicyRevision(rev uint64) {
	if rev <= e.policyRevision {
		return
	}

	now := time.Now()
	e.policyRevision = rev
	e.UpdateLogger(map[string]interface{}{
		logfields.DatapathPolicyRevision: e.policyRevision,
	})
	for ps := range e.policyRevisionSignals {
		select {
		case <-ps.ctx.Done():
			close(ps.ch)
			ps.done(now)
			delete(e.policyRevisionSignals, ps)
		default:
			if rev >= ps.wantedRev {
				close(ps.ch)
				ps.done(now)
				delete(e.policyRevisionSignals, ps)
			}
		}
	}
}

// cleanPolicySignals closes and removes all policy revision signals.
func (e *Endpoint) cleanPolicySignals() {
	now := time.Now()
	for w := range e.policyRevisionSignals {
		w.done(now)
		close(w.ch)
	}
	e.policyRevisionSignals = map[*policySignal]bool{}
}

// policySignal is used to mark when a wanted policy wantedRev is reached
type policySignal struct {
	// wantedRev specifies which policy revision the signal wants.
	wantedRev uint64
	// ch is the channel that signalizes once the policy revision wanted is reached.
	ch chan struct{}
	// ctx is the context for the policy signal request.
	ctx context.Context
	// done is a callback to call for this policySignal. It is in addition to the
	// ch above.
	done func(ts time.Time)
}

// WaitForPolicyRevision returns a channel that is closed when one or more of
// the following conditions have met:
//  - the endpoint is disconnected state
//  - the endpoint's policy revision reaches the wanted revision
// When the done callback is non-nil it will be called just before the channel is closed.
func (e *Endpoint) WaitForPolicyRevision(ctx context.Context, rev uint64, done func(ts time.Time)) <-chan struct{} {
	// NOTE: unconditionalLock is used here because this method handles endpoint in disconnected state on its own
	e.unconditionalLock()
	defer e.unlock()

	if done == nil {
		done = func(time.Time) {}
	}

	ch := make(chan struct{})
	if e.policyRevision >= rev || e.state == StateDisconnected {
		close(ch)
		done(time.Now())
		return ch
	}
	ps := &policySignal{
		wantedRev: rev,
		ctx:       ctx,
		ch:        ch,
		done:      done,
	}
	if e.policyRevisionSignals == nil {
		e.policyRevisionSignals = map[*policySignal]bool{}
	}
	e.policyRevisionSignals[ps] = true
	return ch
}

func (e *Endpoint) setDefaultPolicyConfig() {
	e.SetDefaultOpts(option.Config.Opts)
	alwaysEnforce := policy.GetPolicyEnabled() == option.AlwaysEnforce
	e.desiredPolicy.IngressPolicyEnabled = alwaysEnforce
	e.desiredPolicy.EgressPolicyEnabled = alwaysEnforce
}

// forcePolicyComputation ensures that upon the next policy calculation for this
// Endpoint, that no short-circuiting of said operation occurs.
func (e *Endpoint) forcePolicyComputation() {
	e.forcePolicyCompute = true
}

// GetIngressPolicyEnabledLocked returns whether ingress policy enforcement is
// enabled for endpoint or not. The endpoint's mutex must be held.
func (e *Endpoint) GetIngressPolicyEnabledLocked() bool {
	return e.desiredPolicy.IngressPolicyEnabled
}

// GetEgressPolicyEnabledLocked returns whether egress policy enforcement is
// enabled for endpoint or not. The endpoint's mutex must be held.
func (e *Endpoint) GetEgressPolicyEnabledLocked() bool {
	return e.desiredPolicy.EgressPolicyEnabled
}

// Allows is only used for unit testing
func (e *Endpoint) Allows(id identityPkg.NumericIdentity) bool {
	e.unconditionalRLock()
	defer e.runlock()

	keyToLookup := policy.Key{
		Identity:         uint32(id),
		TrafficDirection: trafficdirection.Ingress.Uint8(),
	}

	_, ok := e.desiredPolicy.PolicyMapState[keyToLookup]
	return ok
}
