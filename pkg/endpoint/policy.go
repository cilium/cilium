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
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/safetime"
	"github.com/cilium/cilium/pkg/uuid"

	"github.com/sirupsen/logrus"
)

// ProxyID returns a unique string to identify a proxy mapping.
func (e *Endpoint) ProxyID(l4 *policy.L4Filter) string {
	return policy.ProxyID(e.ID, l4.Ingress, string(l4.Protocol), uint16(l4.Port))
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
func (e *Endpoint) updateNetworkPolicy(owner Owner, proxyWaitGroup *completion.WaitGroup) (reterr error, revertFunc revert.RevertFunc) {
	// Skip updating the NetworkPolicy if no identity has been computed for this
	// endpoint.
	// This breaks a circular dependency between configuring NetworkPolicies in
	// sidecar Envoy proxies and those proxies needing network connectivity
	// to get their initial configuration, which is required for them to ACK
	// the NetworkPolicies.
	if e.SecurityIdentity == nil {
		return nil, nil
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
	var desiredL4Policy *policy.L4Policy
	if e.desiredPolicy == nil {
		desiredL4Policy = &policy.L4Policy{}
	} else {
		desiredL4Policy = e.desiredPolicy.L4Policy
	}
	return owner.UpdateNetworkPolicy(e, desiredL4Policy, *e.prevIdentityCache, deniedIngressIdentities, deniedEgressIdentities, proxyWaitGroup)
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
// rules in Owner's policy repository.
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
func (e *Endpoint) regeneratePolicy(owner Owner) error {
	var forceRegeneration bool

	// No point in calculating policy if endpoint does not have an identity yet.
	if e.SecurityIdentity == nil {
		e.getLogger().Warn("Endpoint lacks identity, skipping policy calculation")
		return nil
	}

	e.getLogger().Debug("Starting policy recalculation...")

	// Collect label arrays before policy computation, as this can fail.
	// GH-1128 should allow optimizing this away, but currently we can't
	// reliably know if the KV-store has changed or not, so we must scan
	// through it each time.
	identityCache := cache.GetIdentityCache()
	labelsMap := &identityCache

	regenerateStart := time.Now()

	// Use the old labelsMap instance if the new one is still the same.
	// Later we can compare the pointers to figure out if labels have changed or not.
	if reflect.DeepEqual(e.prevIdentityCache, labelsMap) {
		labelsMap = e.prevIdentityCache
	}

	repo := owner.GetPolicyRepository()
	repo.Mutex.RLock()
	revision := repo.GetRevision()
	defer repo.Mutex.RUnlock()

	// Recompute policy for this endpoint only if not already done for this revision.
	// Must recompute if labels have changed.
	if !e.forcePolicyCompute && e.nextPolicyRevision >= revision &&
		labelsMap == e.prevIdentityCache {

		e.getLogger().WithFields(logrus.Fields{
			"policyRevision.next": e.nextPolicyRevision,
			"policyRevision.repo": revision,
			"policyChanged":       e.nextPolicyRevision > e.policyRevision,
		}).Debug("Skipping unnecessary endpoint policy recalculation")

		return nil
	}

	// Update fields within endpoint based off known identities, and whether
	// policy needs to be enforced for either ingress or egress.
	e.prevIdentityCache = labelsMap

	calculatedPolicy, err := repo.ResolvePolicy(e.ID, e.SecurityIdentity.LabelArray, e, *labelsMap)
	if err != nil {
		return err
	}

	e.desiredPolicy = calculatedPolicy

	if e.forcePolicyCompute {
		forceRegeneration = true     // Options were changed by the caller.
		e.forcePolicyCompute = false // Policies just computed
		e.getLogger().Debug("Forced policy recalculation")
	}

	// Set the revision of this endpoint to the current revision of the policy
	// repository.
	e.setNextPolicyRevision(revision)

	logger := e.getLogger().WithFields(logrus.Fields{
		"forcedRegeneration": forceRegeneration,
	})

	totalRegeneration, _ := safetime.TimeSinceSafe(regenerateStart, logger)

	logger.WithField(logfields.PolicyRegenerationTime, totalRegeneration.String()).
		Debug("Completed endpoint policy recalculation")

	regenerateTimeSec := totalRegeneration.Seconds()
	metrics.PolicyRegenerationCount.Inc()
	metrics.PolicyRegenerationTime.Add(regenerateTimeSec)
	metrics.PolicyRegenerationTimeSquare.Add(math.Pow(regenerateTimeSec, 2))

	return nil
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

// Called with e.Mutex UNlocked
func (e *Endpoint) regenerate(owner Owner, context *regenerationContext) (retErr error) {
	var revision uint64
	var compilationExecuted bool
	var err error

	context.Stats = regenerationStatistics{}
	stats := &context.Stats
	metrics.EndpointCountRegenerating.Inc()
	stats.totalTime.Start()
	e.getLogger().WithFields(logrus.Fields{
		logfields.StartTime: time.Now(),
		logfields.Reason:    context.Reason,
	}).Info("Regenerating endpoint")

	defer func() {
		e.updateRegenerationStatistics(context, retErr)
	}()

	e.BuildMutex.Lock()
	defer e.BuildMutex.Unlock()

	stats.waitingForLock.Start()
	// Check if endpoints is still alive before doing any build
	err = e.LockAlive()
	stats.waitingForLock.End(err == nil)
	if err != nil {
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

	stats.prepareBuild.Start()
	origDir := filepath.Join(option.Config.StateDir, e.StringID())
	context.datapathRegenerationContext.currentDir = origDir

	// This is the temporary directory to store the generated headers,
	// the original existing directory is not overwritten until the
	// entire generation process has succeeded.
	tmpDir := e.NextDirectoryPath()
	context.datapathRegenerationContext.nextDir = tmpDir

	// Remove an eventual existing temporary directory that has been left
	// over to make sure we can start the build from scratch
	if err := e.removeDirectory(tmpDir); err != nil && !os.IsNotExist(err) {
		stats.prepareBuild.End(false)
		return fmt.Errorf("unable to remove old temporary directory: %s", err)
	}

	// Create temporary endpoint directory if it does not exist yet
	if err := os.MkdirAll(tmpDir, 0777); err != nil {
		stats.prepareBuild.End(false)
		return fmt.Errorf("Failed to create endpoint directory: %s", err)
	}

	stats.prepareBuild.End(true)

	defer func() {
		if err := e.LockAlive(); err != nil {
			if retErr == nil {
				retErr = err
			} else {
				e.LogDisconnectedMutexAction(err, "after regenerate")
			}
			return
		}

		// Guarntee removal of temporary directory regardless of outcome of
		// build. If the build was successful, the temporary directory will
		// have been moved to a new permanent location. If the build failed,
		// the temporary directory will still exist and we will reomve it.
		e.removeDirectory(tmpDir)

		// Set to Ready, but only if no other changes are pending.
		// State will remain as waiting-to-regenerate if further
		// changes are needed. There should be an another regenerate
		// queued for taking care of it.
		e.BuilderSetStateLocked(StateReady, "Completed endpoint regeneration with no pending regeneration requests")
		e.Unlock()
	}()

	revision, compilationExecuted, err = e.regenerateBPF(owner, context)
	if err != nil {
		failDir := e.FailedDirectoryPath()
		e.getLogger().WithFields(logrus.Fields{
			logfields.Path: failDir,
		}).Warn("generating BPF for endpoint failed, keeping stale directory.")

		// Remove an eventual existing previous failure directory
		e.removeDirectory(failDir)
		os.Rename(tmpDir, failDir)
		return err
	}

	return e.updateRealizedState(stats, origDir, revision, compilationExecuted)
}

// updateRealizedState sets any realized state fields within the endpoint to
// be the desired state of the endpoint. This is only called after a successful
// regeneration of the endpoint.
func (e *Endpoint) updateRealizedState(stats *regenerationStatistics, origDir string, revision uint64, compilationExecuted bool) error {
	// Update desired policy for endpoint because policy has now been realized
	// in the datapath. PolicyMap state is not updated here, because that is
	// performed in endpoint.syncPolicyMap().
	stats.waitingForLock.Start()
	err := e.LockAlive()
	stats.waitingForLock.End(err == nil)
	if err != nil {
		return err
	}

	defer e.Unlock()

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

	e.realizedBPFConfig = e.desiredBPFConfig

	if e.realizedPolicy == nil {
		e.realizedPolicy = &policy.EndpointPolicy{}
	}

	e.realizedPolicy.IngressPolicyEnabled = e.desiredPolicy.IngressPolicyEnabled
	e.realizedPolicy.EgressPolicyEnabled = e.desiredPolicy.EgressPolicyEnabled
	e.realizedPolicy.L4Policy = e.desiredPolicy.L4Policy
	e.realizedPolicy.CIDRPolicy = e.desiredPolicy.CIDRPolicy

	// Mark the endpoint to be running the policy revision it was
	// compiled for
	e.setPolicyRevision(revision)

	return nil
}

func (e *Endpoint) updateRegenerationStatistics(context *regenerationContext, err error) {
	success := err == nil
	stats := &context.Stats

	stats.totalTime.End(success)
	stats.success = success

	e.mutex.RLock()
	stats.endpointID = e.ID
	stats.policyStatus = e.policyStatus()
	e.RUnlock()
	stats.SendMetrics()

	scopedLog := e.getLogger().WithFields(logrus.Fields{
		"waitingForLock":         stats.waitingForLock.Total(),
		"waitingForCTClean":      stats.waitingForCTClean.Total(),
		"policyCalculation":      stats.policyCalculation.Total(),
		"proxyConfiguration":     stats.proxyConfiguration.Total(),
		"proxyPolicyCalculation": stats.proxyPolicyCalculation.Total(),
		"proxyWaitForAck":        stats.proxyWaitForAck.Total(),
		"bpfCompilation":         stats.bpfCompilation.Total(),
		"mapSync":                stats.mapSync.Total(),
		"prepareBuild":           stats.prepareBuild.Total(),
		logfields.BuildDuration:  stats.totalTime.Total(),
		logfields.Reason:         context.Reason,
	})

	if err != nil {
		scopedLog.WithError(err).Warn("Regeneration of endpoint failed")
		e.LogStatus(BPF, Failure, "Error regenerating endpoint: "+err.Error())
		return
	}

	scopedLog.Info("Completed endpoint regeneration")
	e.LogStatusOK(BPF, "Successfully regenerated endpoint program (Reason: "+context.Reason+")")
}

// Regenerate forces the regeneration of endpoint programs & policy
// Should only be called with e.state == StateWaitingToRegenerate or with
// e.state == StateWaitingForIdentity
func (e *Endpoint) Regenerate(owner Owner, regenMetadata *ExternalRegenerationMetadata) <-chan bool {
	done := make(chan bool, 1)

	go func() {
		var buildSuccess bool

		regenContext := regenMetadata.toRegenerationContext()

		defer func() {
			done <- buildSuccess
			close(done)
		}()

		err := e.RLockAlive()
		if err != nil {
			e.LogDisconnectedMutexAction(err, "before regeneration")
			return
		}
		e.RUnlock()
		scopedLog := e.getLogger()

		// We should only queue the request after we use all the endpoint's
		// lock/unlock. Otherwise this can get a deadlock if the endpoint is
		// being deleted at the same time. More info PR-1777.
		doneFunc := owner.QueueEndpointBuild(uint64(e.ID))
		if doneFunc != nil {
			scopedLog.Debug("Dequeued endpoint from build queue")

			regenContext.DoneFunc = doneFunc
			err := e.regenerate(owner, regenContext)
			doneFunc() // in case not called already

			repr, reprerr := monitor.EndpointRegenRepr(e, err)
			if reprerr != nil {
				scopedLog.WithError(reprerr).Warn("Notifying monitor about endpoint regeneration failed")
			}

			if err != nil {
				buildSuccess = false
				if reprerr == nil && !option.Config.DryMode {
					owner.SendNotification(monitor.AgentNotifyEndpointRegenerateFail, repr)
				}
			} else {
				buildSuccess = true
				if reprerr == nil && !option.Config.DryMode {
					owner.SendNotification(monitor.AgentNotifyEndpointRegenerateSuccess, repr)
				}
			}
		} else {
			buildSuccess = false
			scopedLog.Debug("My request was cancelled because I'm already in line")
		}
	}()
	return done
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

				// This is equivalent to checking if K8s is enabled, but by
				// checking endpoint state instead.
				if id != "" && e.GetK8sNamespace() != "" && e.GetK8sPodName() != "" {
					if EpAnnotator != nil {
						err := EpAnnotator.AnnotatePod(e.GetK8sNamespace(), e.GetK8sPodName(), k8sConst.CiliumIdentityAnnotation, id)
						if err == nil {
							log.WithFields(logrus.Fields{
								logfields.EndpointID:            e.StringID(),
								logfields.K8sNamespace:          e.GetK8sNamespace(),
								logfields.K8sPodName:            e.GetK8sPodName(),
								logfields.K8sIdentityAnnotation: k8sConst.CiliumIdentityAnnotation,
								logfields.RetryUUID:             uuid.NewUUID(),
							}).Debugf("Successfully annotated endpoint with %s=%s", logfields.K8sIdentityAnnotation, id)
						}
						return err
					}
					e.getLogger().Warningf("unable to annotate corresponding pod due to nil annotator")
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
	metadata := []string{endpointid.CiliumGlobalIdPrefix.String(), ipcache.AddressSpace, n.Name, strconv.Itoa(int(e.ID))}
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
	istioSidecarProxyLabel, found := identity.Labels[k8sConst.PolicyLabelIstioSidecarProxy]
	e.hasSidecarProxy = found &&
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
