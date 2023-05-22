// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/controller"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/eventqueue"
	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipcache"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

// GetNamedPort returns the port for the given name.
// Must be called with e.mutex NOT held
func (e *Endpoint) GetNamedPort(ingress bool, name string, proto uint8) uint16 {
	if ingress {
		// Ingress only needs the ports of the POD itself
		k8sPorts, err := e.GetK8sPorts()
		if err != nil {
			if e.logLimiter.Allow() {
				e.getLogger().WithFields(logrus.Fields{
					logfields.PortName:         name,
					logfields.Protocol:         u8proto.U8proto(proto).String(),
					logfields.TrafficDirection: "ingress",
				}).WithError(err).Warning("Skipping named port")
			}
			return 0
		}
		return e.getNamedPortIngress(k8sPorts, name, proto)
	}
	// egress needs named ports of all the pods
	return e.getNamedPortEgress(e.namedPortsGetter.GetNamedPorts(), name, proto)
}

// GetNamedPortLocked returns port for the given name. May return an invalid (0) port
// Must be called with e.mutex held.
func (e *Endpoint) GetNamedPortLocked(ingress bool, name string, proto uint8) uint16 {
	if ingress {
		// Ingress only needs the ports of the POD itself
		return e.getNamedPortIngress(e.k8sPorts, name, proto)
	}
	// egress needs named ports of all the pods
	return e.getNamedPortEgress(e.namedPortsGetter.GetNamedPorts(), name, proto)
}

func (e *Endpoint) getNamedPortIngress(npMap types.NamedPortMap, name string, proto uint8) uint16 {
	port, err := npMap.GetNamedPort(name, proto)
	if err != nil && e.logLimiter.Allow() {
		e.getLogger().WithFields(logrus.Fields{
			logfields.PortName:         name,
			logfields.Protocol:         u8proto.U8proto(proto).String(),
			logfields.TrafficDirection: "ingress",
		}).WithError(err).Warning("Skipping named port")
	}
	return port
}

func (e *Endpoint) getNamedPortEgress(npMap types.NamedPortMultiMap, name string, proto uint8) uint16 {
	port, err := npMap.GetNamedPort(name, proto)
	// Skip logging for ErrUnknownNamedPort on egress, as the destination POD with the port name
	// is likely not scheduled yet.
	if err != nil && !errors.Is(err, types.ErrUnknownNamedPort) && e.logLimiter.Allow() {
		e.getLogger().WithFields(logrus.Fields{
			logfields.PortName:         name,
			logfields.Protocol:         u8proto.U8proto(proto).String(),
			logfields.TrafficDirection: "egress",
		}).WithError(err).Warning("Skipping named port")
	}
	return port
}

// proxyID returns a unique string to identify a proxy mapping.
// Must be called with e.mutex held.
func (e *Endpoint) proxyID(l4 *policy.L4Filter) string {
	port := uint16(l4.Port)
	if port == 0 && l4.PortName != "" {
		port = e.GetNamedPortLocked(l4.Ingress, l4.PortName, uint8(l4.U8Proto))
		if port == 0 {
			return ""
		}
	}
	return policy.ProxyID(e.ID, l4.Ingress, string(l4.Protocol), port)
}

// lookupRedirectPort returns the redirect L4 proxy port for the given L4
// policy map key, in host byte order. Returns 0 if not found or the
// filter doesn't require a redirect.
// Must be called with Endpoint.mutex held.
func (e *Endpoint) LookupRedirectPortLocked(ingress bool, protocol string, port uint16) uint16 {
	return e.realizedRedirects[policy.ProxyID(e.ID, ingress, protocol, port)]
}

// Note that this function assumes that endpoint policy has already been generated!
// must be called with endpoint.mutex held for reading
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
		return nil, nil
	}

	// Publish the updated policy to L7 proxies.
	return e.proxy.UpdateNetworkPolicy(e, e.visibilityPolicy, e.desiredPolicy.L4Policy, e.desiredPolicy.IngressPolicyEnabled, e.desiredPolicy.EgressPolicyEnabled, proxyWaitGroup)
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
//   - err: any error in obtaining information for computing policy, or if
//
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
	repo := e.policyGetter.GetPolicyRepository()
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
		"waitingForIdentityCache":    &stats.waitingForIdentityCache,
		"waitingForPolicyRepository": &stats.waitingForPolicyRepository,
		"policyCalculation":          &stats.policyCalculation,
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

	optsChanged = e.applyOptsLocked(opts)
	return
}

// Called with e.mutex UNlocked
func (e *Endpoint) regenerate(ctx *regenerationContext) (retErr error) {
	var revision uint64
	var stateDirComplete bool
	var err error

	ctx.Stats = regenerationStatistics{}
	stats := &ctx.Stats
	stats.totalTime.Start()
	e.getLogger().WithFields(logrus.Fields{
		logfields.StartTime: time.Now(),
		logfields.Reason:    ctx.Reason,
	}).Debug("Regenerating endpoint")

	defer func() {
		// This has to be within a func(), not deferred directly, so that the
		// value of retErr is passed in from when regenerate returns.
		e.updateRegenerationStatistics(ctx, retErr)
	}()

	e.buildMutex.Lock()
	defer e.buildMutex.Unlock()

	stats.waitingForLock.Start()
	// Check if endpoints is still alive before doing any build
	err = e.lockAlive()
	stats.waitingForLock.End(err == nil)
	if err != nil {
		return err
	}

	// When building the initial drop policy in waiting-for-identity state
	// the state remains unchanged
	//
	// GH-5350: Remove this special case to require checking for StateWaitingForIdentity
	if e.getState() != StateWaitingForIdentity &&
		!e.BuilderSetStateLocked(StateRegenerating, "Regenerating endpoint: "+ctx.Reason) {
		e.getLogger().WithField(logfields.EndpointState, e.state).Debug("Skipping build due to invalid state")
		e.unlock()

		return fmt.Errorf("Skipping build due to invalid state: %s", e.state)
	}

	// Bump priority if higher priority event was skipped.
	// This must be done in the same critical section as the state transition above.
	if e.skippedRegenerationLevel > ctx.datapathRegenerationContext.regenerationLevel {
		ctx.datapathRegenerationContext.regenerationLevel = e.skippedRegenerationLevel
	}
	// reset to the default lowest level
	e.skippedRegenerationLevel = regeneration.Invalid

	e.unlock()

	stats.prepareBuild.Start()
	origDir := e.StateDirectoryPath()
	ctx.datapathRegenerationContext.currentDir = origDir

	// This is the temporary directory to store the generated headers,
	// the original existing directory is not overwritten until the
	// entire generation process has succeeded.
	tmpDir := e.NextDirectoryPath()
	ctx.datapathRegenerationContext.nextDir = tmpDir

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
		if err := e.lockAlive(); err != nil {
			if retErr == nil {
				retErr = err
			} else {
				e.logDisconnectedMutexAction(err, "after regenerate")
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
		e.unlock()
	}()

	revision, stateDirComplete, err = e.regenerateBPF(ctx)

	// Write full verifier log to the endpoint directory.
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		p := path.Join(tmpDir, "verifier.log")
		f, err := os.Create(p)
		if err != nil {
			return fmt.Errorf("creating endpoint verifier log file: %w", err)
		}
		if _, err := fmt.Fprintf(f, "%+v\n", ve); err != nil {
			return fmt.Errorf("writing verifier log to endpoint directory: %w", err)
		}
		e.getLogger().WithFields(logrus.Fields{logfields.Path: p}).
			Info("Wrote verifier log to endpoint directory")
	}

	if err != nil {
		failDir := e.FailedDirectoryPath()
		if !errors.Is(err, context.Canceled) {
			e.getLogger().WithError(err).WithFields(logrus.Fields{logfields.Path: failDir}).
				Info("generating BPF for endpoint failed, keeping stale directory")
		}

		// Remove an eventual existing previous failure directory
		e.removeDirectory(failDir)
		os.Rename(tmpDir, failDir)
		return err
	}

	return e.updateRealizedState(stats, origDir, revision, stateDirComplete)
}

// updateRealizedState sets any realized state fields within the endpoint to
// be the desired state of the endpoint. This is only called after a successful
// regeneration of the endpoint.
func (e *Endpoint) updateRealizedState(stats *regenerationStatistics, origDir string, revision uint64, stateDirComplete bool) error {
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
	err = e.synchronizeDirectories(origDir, stateDirComplete)
	if err != nil {
		return fmt.Errorf("error synchronizing endpoint BPF program directories: %s", err)
	}

	// Keep PolicyMap for this endpoint in sync with desired / realized state.
	if !option.Config.DryMode {
		e.syncPolicyMapController()
	}

	if e.desiredPolicy != e.realizedPolicy {
		// Remove references to the old policy
		e.realizedPolicy.Detach()
		// Set realized state to desired state.
		e.realizedPolicy = e.desiredPolicy
	}

	// Mark the endpoint to be running the policy revision it was
	// compiled for
	e.setPolicyRevision(revision)

	// Remove restored rules after successful regeneration
	e.owner.RemoveRestoredDNSRules(e.ID)

	return nil
}

func (e *Endpoint) updateRegenerationStatistics(ctx *regenerationContext, err error) {
	success := err == nil
	stats := &ctx.Stats

	stats.totalTime.End(success)
	stats.success = success

	e.mutex.RLock()
	stats.endpointID = e.ID
	stats.policyStatus = e.policyStatus()
	e.runlock()
	stats.SendMetrics()

	fields := logrus.Fields{
		logfields.Reason: ctx.Reason,
	}
	for field, stat := range stats.GetMap() {
		fields[field] = stat.Total()
	}
	for field, stat := range stats.datapathRealization.GetMap() {
		fields[field] = stat.Total()
	}
	scopedLog := e.getLogger().WithFields(fields)

	if err != nil {
		if !errors.Is(err, context.Canceled) {
			scopedLog.WithError(err).Warn("Regeneration of endpoint failed")
		}
		e.LogStatus(BPF, Failure, "Error regenerating endpoint: "+err.Error())
		return
	}

	scopedLog.Debug("Completed endpoint regeneration")
	e.LogStatusOK(BPF, "Successfully regenerated endpoint program (Reason: "+ctx.Reason+")")
}

// SetRegenerateStateIfAlive tries to change the state of the endpoint for pending regeneration.
// Returns 'true' if 'e.Regenerate()' should be called after releasing the endpoint lock.
// Return 'false' if returned error is non-nil.
func (e *Endpoint) SetRegenerateStateIfAlive(regenMetadata *regeneration.ExternalRegenerationMetadata) (bool, error) {
	regen := false
	err := e.lockAlive()
	if err != nil {
		e.LogStatus(Policy, Failure, "Error while handling policy updates for endpoint: "+err.Error())
	} else {
		regen = e.setRegenerateStateLocked(regenMetadata)
		e.unlock()
	}
	return regen, err
}

// setRegenerateStateLocked tries to change the state of the endpoint for pending regeneration.
// returns 'true' if 'e.Regenerate()' should be called after releasing the endpoint lock.
func (e *Endpoint) setRegenerateStateLocked(regenMetadata *regeneration.ExternalRegenerationMetadata) bool {
	var regen bool
	state := e.getState()
	switch state {
	case StateRestoring, StateWaitingToRegenerate:
		// Bump the skipped regeneration level if needed so that the existing/queued
		// regeneration can regenerate on the required level.
		if regenMetadata.RegenerationLevel > e.skippedRegenerationLevel {
			e.skippedRegenerationLevel = regenMetadata.RegenerationLevel
			e.logStatusLocked(Other, OK, fmt.Sprintf("Skipped duplicate endpoint regeneration level %s trigger due to %s", regenMetadata.RegenerationLevel.String(), regenMetadata.Reason))
		} else {
			e.logStatusLocked(Other, OK, fmt.Sprintf("Skipped duplicate endpoint regeneration trigger due to %s", regenMetadata.Reason))
		}
		regen = false
	default:
		regen = e.setState(StateWaitingToRegenerate, fmt.Sprintf("Triggering endpoint regeneration due to %s", regenMetadata.Reason))
	}
	return regen
}

// RegenerateIfAlive queue a regeneration of this endpoint into the build queue
// of the endpoint and returns a channel that is closed when the regeneration of
// the endpoint is complete. The channel returns:
//   - false if the regeneration failed
//   - true if the regeneration succeed
//   - nothing and the channel is closed if the regeneration did not happen
func (e *Endpoint) RegenerateIfAlive(regenMetadata *regeneration.ExternalRegenerationMetadata) <-chan bool {
	regen, err := e.SetRegenerateStateIfAlive(regenMetadata)
	if err != nil {
		log.WithError(err).Debugf("Endpoint disappeared while queued to be regenerated: %s", regenMetadata.Reason)
	}
	if regen {
		// Regenerate logs status according to the build success/failure
		return e.Regenerate(regenMetadata)
	}

	ch := make(chan bool)
	close(ch)
	return ch
}

// Regenerate forces the regeneration of endpoint programs & policy
// Should only be called with e.state at StateWaitingToRegenerate,
// StateWaitingForIdentity, or StateRestoring
func (e *Endpoint) Regenerate(regenMetadata *regeneration.ExternalRegenerationMetadata) <-chan bool {
	done := make(chan bool, 1)

	var (
		ctx   context.Context
		cFunc context.CancelFunc
	)

	if regenMetadata.ParentContext != nil {
		ctx, cFunc = context.WithCancel(regenMetadata.ParentContext)
	} else {
		ctx, cFunc = context.WithCancel(e.aliveCtx)
	}

	regenContext := ParseExternalRegenerationMetadata(ctx, cFunc, regenMetadata)

	epEvent := eventqueue.NewEvent(&EndpointRegenerationEvent{
		regenContext: regenContext,
		ep:           e,
	})

	// This may block if the Endpoint's EventQueue is full. This has to be done
	// synchronously as some callers depend on the fact that the event is
	// synchronously enqueued.
	resChan, err := e.eventQueue.Enqueue(epEvent)
	if err != nil {
		e.getLogger().WithError(err).Error("Enqueue of EndpointRegenerationEvent failed")
		done <- false
		close(done)
		return done
	}

	go func() {

		// Free up resources with context.
		defer cFunc()

		var (
			buildSuccess bool
			regenError   error
			canceled     bool
		)

		select {
		case result, ok := <-resChan:
			if ok {
				regenResult := result.(*EndpointRegenerationResult)
				regenError = regenResult.err
				buildSuccess = regenError == nil

				if regenError != nil && !errors.Is(regenError, context.Canceled) {
					e.getLogger().WithError(regenError).Error("endpoint regeneration failed")
				}
			} else {
				// This may be unnecessary(?) since 'closing' of the results
				// channel means that event has been cancelled?
				e.getLogger().Debug("regeneration was cancelled")
				canceled = true
			}
		}

		// If a build is canceled, that means that the Endpoint is being deleted
		// not that the build failed.
		if !buildSuccess && !canceled {
			select {
			case e.regenFailedChan <- struct{}{}:
			default:
				// If we can't write to the channel, that means that it is
				// full / a regeneration will occur - we don't have to
				// do anything.
			}
		}
		done <- buildSuccess
		close(done)
	}()

	return done
}

var reasonRegenRetry = "retrying regeneration"

// startRegenerationFailureHandler waits for a build of the Endpoint to fail.
// Terminates when the given Endpoint is deleted.
// If a build fails, the controller tries to regenerate the
// Endpoint until it succeeds. Once the controller succeeds, it will not be
// ran again unless another build failure occurs. If the call to `Regenerate`
// fails inside of the controller,
func (e *Endpoint) startRegenerationFailureHandler() {
	e.controllers.UpdateController(fmt.Sprintf("endpoint-%s-regeneration-recovery", e.StringID()), controller.ControllerParams{
		DoFunc: func(ctx context.Context) error {
			select {
			case <-e.regenFailedChan:
				e.getLogger().Debug("received signal that regeneration failed")
			case <-ctx.Done():
				e.getLogger().Debug("exiting retrying regeneration goroutine due to endpoint being deleted")
				return nil
			}

			regenMetadata := &regeneration.ExternalRegenerationMetadata{
				// TODO (ianvernon) - is there a way we can plumb a parent
				// context to a controller (e.g., endpoint.aliveCtx)?
				ParentContext: ctx,
				Reason:        reasonRegenRetry,
				// Completely rewrite the endpoint - we don't know the nature
				// of the failure, simply that something failed.
				RegenerationLevel: regeneration.RegenerateWithDatapathRewrite,
			}
			regen, _ := e.SetRegenerateStateIfAlive(regenMetadata)
			if !regen {
				// We don't need to regenerate because the endpoint is d
				// disconnecting / is disconnected, or another regeneration has
				// already been enqueued. Exit gracefully.
				return nil
			}

			if success := <-e.Regenerate(regenMetadata); success {
				return nil
			}
			return fmt.Errorf("regeneration recovery failed")
		},
		ErrorRetryBaseDuration: 2 * time.Second,
		Context:                e.aliveCtx,
	})
}

func (e *Endpoint) notifyEndpointRegeneration(err error) {
	reprerr := e.owner.SendNotification(monitorAPI.EndpointRegenMessage(e, err))
	if reprerr != nil {
		e.getLogger().WithError(reprerr).Warn("Notifying monitor about endpoint regeneration failed")
	}
}

// FormatGlobalEndpointID returns the global ID of endpoint in the format
// / <global ID Prefix>:<cluster name>:<node name>:<endpoint ID> as a string.
func (e *Endpoint) FormatGlobalEndpointID() string {
	localNodeName := nodeTypes.GetName()
	metadata := []string{endpointid.CiliumGlobalIdPrefix.String(), ipcache.AddressSpace, localNodeName, strconv.Itoa(int(e.ID))}
	return strings.Join(metadata, ":")
}

// This synchronizes the key-value store with a mapping of the endpoint's IP
// with the numerical ID representing its security identity.
func (e *Endpoint) runIPIdentitySync(endpointIP netip.Addr) {
	if option.Config.KVStore == "" || !endpointIP.IsValid() || option.Config.JoinCluster {
		return
	}

	addressFamily := "IPv4"
	if endpointIP.Is6() {
		addressFamily = "IPv6"
	}

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

				ID := e.SecurityIdentity.ID
				hostIP, ok := ip.AddrFromIP(node.GetIPv4())
				if !ok {
					return controller.NewExitReason("Failed to convert node IPv4 address")
				}
				key := node.GetIPsecKeyIdentity()
				metadata := e.FormatGlobalEndpointID()
				k8sNamespace := e.K8sNamespace
				k8sPodName := e.K8sPodName
				namedPorts := e.k8sPorts

				// Release lock as we do not want to have long-lasting key-value
				// store operations resulting in lock being held for a long time.
				e.runlock()

				if err := ipcache.UpsertIPToKVStore(ctx, endpointIP, hostIP, ID, key, metadata, k8sNamespace, k8sPodName, namedPorts); err != nil {
					return fmt.Errorf("unable to add endpoint IP mapping '%s'->'%d': %s", endpointIP.String(), ID, err)
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
			Context:     e.aliveCtx,
		},
	)
}

// SetIdentity resets endpoint's policy identity to 'id'.
// Caller triggers policy regeneration if needed.
// Called with e.mutex Lock()ed
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
	return e.owner.GetCIDRPrefixLengths()
}

// AnnotationsResolverCB provides an implementation for resolving the pod
// annotations.
type AnnotationsResolverCB func(ns, podName string) (proxyVisibility string, err error)

// UpdateNoTrackRules updates the NOTRACK iptable rules for this endpoint. If anno
// is empty, then any existing NOTRACK rules will be removed. If anno cannot be parsed,
// we remove existing NOTRACK rules too if there's any.
func (e *Endpoint) UpdateNoTrackRules(annoCB AnnotationsResolverCB) {
	ch, err := e.eventQueue.Enqueue(eventqueue.NewEvent(&EndpointNoTrackEvent{
		ep:     e,
		annoCB: annoCB,
	}))
	if err != nil {
		e.getLogger().WithError(err).Error("Unable to enqueue endpoint notrack event")
		return
	}

	updateRes := <-ch
	regenResult, ok := updateRes.(*EndpointRegenerationResult)
	if ok && regenResult.err != nil {
		e.getLogger().WithError(regenResult.err).Error("EndpointNoTrackEvent event failed")
	}
}

// UpdateVisibilityPolicy updates the visibility policy of this endpoint to
// reflect the state stored in the provided proxy visibility annotation. If anno
// is empty, then the VisibilityPolicy for the Endpoint will be empty, and will
// have no effect. If the proxy visibility annotation cannot be parsed, an empty
// visibility policy is assigned to the Endpoint.
func (e *Endpoint) UpdateVisibilityPolicy(annoCB AnnotationsResolverCB) {
	ch, err := e.eventQueue.Enqueue(eventqueue.NewEvent(&EndpointPolicyVisibilityEvent{
		ep:     e,
		annoCB: annoCB,
	}))
	if err != nil {
		e.getLogger().WithError(err).Error("Unable to enqueue endpoint policy visibility event")
		return
	}

	updateRes := <-ch
	regenResult, ok := updateRes.(*EndpointRegenerationResult)
	if ok && regenResult.err != nil {
		e.getLogger().WithError(regenResult.err).Error("EndpointPolicyVisibilityEvent event failed")
	}
}

// UpdateBandwidthPolicy updates the egress bandwidth of this endpoint to
// progagate the throttle rate to the BPF data path.
func (e *Endpoint) UpdateBandwidthPolicy(annoCB AnnotationsResolverCB) {
	ch, err := e.eventQueue.Enqueue(eventqueue.NewEvent(&EndpointPolicyBandwidthEvent{
		ep:     e,
		annoCB: annoCB,
	}))
	if err != nil {
		e.getLogger().WithError(err).Error("Unable to enqueue endpoint policy bandwidth event")
		return
	}

	updateRes := <-ch
	regenResult, ok := updateRes.(*EndpointRegenerationResult)
	if ok && regenResult.err != nil {
		e.getLogger().WithError(regenResult.err).Error("EndpointPolicyBandwidthEvent event failed")
	}
}

// GetRealizedPolicyRuleLabelsForKey returns the list of policy rule labels
// which match a given flow key (in host byte-order). The returned
// LabelArrayList is shallow-copied and therefore must not be mutated.
// This function explicitly exported to be accessed by code outside of the
// Cilium source code tree and for testing.
func (e *Endpoint) GetRealizedPolicyRuleLabelsForKey(key policy.Key) (
	derivedFrom labels.LabelArrayList,
	revision uint64,
	ok bool,
) {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	entry, ok := e.realizedPolicy.PolicyMapState[key]
	if !ok {
		return nil, 0, false
	}

	return entry.DerivedFromRules, e.policyRevision, true
}
