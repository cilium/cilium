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

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/controller"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	dptypes "github.com/cilium/cilium/pkg/datapath/types"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/eventqueue"
	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

var (
	endpointRegenerationRecoveryControllerGroup = controller.NewGroup("endpoint-regeneration-recovery")
	syncAddressIdentityMappingControllerGroup   = controller.NewGroup("sync-address-identity-mapping")
)

// HasBPFPolicyMap returns true if policy map changes should be collected
// Deprecated: use (e *Endpoint).IsProperty(PropertySkipBPFPolicy)
func (e *Endpoint) HasBPFPolicyMap() bool {
	return !e.IsProperty(PropertySkipBPFPolicy)
}

// GetNamedPort returns the port for the given name.
// Must be called with e.mutex NOT held
func (e *Endpoint) GetNamedPort(ingress bool, name string, proto uint8) uint16 {
	if ingress {
		// Ingress only needs the ports of the POD itself
		return e.getNamedPortIngress(e.GetK8sPorts(), name, proto)
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

// proxyID returns a unique string to identify a proxy mapping,
// and the resolved destination port number, if any.
// For port ranges the proxy is identified by the first port in
// the range, as overlapping proxy port ranges are not supported.
// Must be called with e.mutex held.
func (e *Endpoint) proxyID(l4 *policy.L4Filter, listener string) (string, uint16, uint8) {
	port := l4.Port
	protocol := uint8(l4.U8Proto)
	// Calculate protocol if it is 0 (default) and
	// is not "ANY" (that is, it was not calculated).
	if protocol == 0 && !l4.Protocol.IsAny() {
		proto, _ := u8proto.ParseProtocol(string(l4.Protocol))
		protocol = uint8(proto)
	}
	if port == 0 && l4.PortName != "" {
		port = e.GetNamedPort(l4.Ingress, l4.PortName, protocol)
		if port == 0 {
			return "", 0, 0
		}
	}

	return policy.ProxyID(e.ID, l4.Ingress, string(l4.Protocol), port, listener), port, protocol
}

var unrealizedRedirect = errors.New("Proxy port for redirect not found")

// LookupRedirectPort returns the redirect L4 proxy port for the given input parameters.
// Returns 0 if not found or the filter doesn't require a redirect.
// Returns an error if the redirect port can not be found.
func (e *Endpoint) LookupRedirectPort(ingress bool, protocol string, port uint16, listener string) (uint16, error) {
	redirects := e.GetRealizedRedirects()
	proxyPort, exists := redirects[policy.ProxyID(e.ID, ingress, protocol, port, listener)]
	if !exists {
		return 0, unrealizedRedirect
	}
	return proxyPort, nil
}

// Note that this function assumes that endpoint policy has already been generated!
// must be called with endpoint.mutex held for reading
func (e *Endpoint) updateNetworkPolicy(proxyWaitGroup *completion.WaitGroup) (reterr error, revertFunc revert.RevertFunc) {
	// Skip updating the NetworkPolicy if no identity has been computed for this
	// endpoint.
	if e.SecurityIdentity == nil {
		return nil, nil
	}

	// If desired policy is nil then no policy change is needed.
	if e.desiredPolicy == nil {
		return nil, nil
	}

	if e.IsProxyDisabled() {
		return nil, nil
	}

	// Publish the updated policy to L7 proxies.
	return e.proxy.UpdateNetworkPolicy(e, e.visibilityPolicy, &e.desiredPolicy.L4Policy, e.desiredPolicy.IngressPolicyEnabled, e.desiredPolicy.EgressPolicyEnabled, proxyWaitGroup)
}

// setNextPolicyRevision updates the desired policy revision field
// Must be called with the endpoint lock held for at least reading
func (e *Endpoint) setNextPolicyRevision(revision uint64) {
	e.nextPolicyRevision = revision
	e.UpdateLogger(map[string]interface{}{
		logfields.DesiredPolicyRevision: e.nextPolicyRevision,
	})
}

type policyGenerateResult struct {
	policyRevision   uint64
	selectorPolicy   policy.SelectorPolicy
	endpointPolicy   *policy.EndpointPolicy
	identityRevision int
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
// Failure may be due to any error in obtaining information for computing policy,
// or if policy could not be generated given the current set of rules in the repository.
//
// endpoint lock must NOT be held. This is because the ipcache needs to be able to
// make progress while generating policy, and *that* needs the endpoint unlocked to call
// ep.ApplyPolicyMapChanges. Specifically, computing policy may cause identity allocation
// which requires ipcache progress.
//
// buildMutex MUST be held, and not released until setDesiredPolicy and
// updateRealizedState have been called
//
// There are a few fields that depend on this exact configuration of locking:
//   - ep.desiredPolicy: ep.mutex must be locked between writing this and committing to
//     the policy maps, or else policy drops may occur
//   - ep.policyRevision: ep.mutex and ep.buildMutex must be held to write to this
//   - ep.selectorPolicy: this may be nulled if the endpoints identity changes; we must
//     check for this when committing. ep.mutex must be held
//   - ep.realizedRedirects: this is read by external callers as part of policy generation,
//     so ep.mutex must not be required to read this. Instead, both ep.mutex and ep.buildMutex
//     must be held to write to this (i.e. we are deep in regeneration)
//
// Returns a result that should be passed to setDesiredPolicy after the endpoint's
// write lock has been acquired, or err if recomputing policy failed.
func (e *Endpoint) regeneratePolicy(stats *regenerationStatistics) (*policyGenerateResult, error) {
	var err error

	// lock the endpoint, read our values, then unlock
	err = e.rlockAlive()
	if err != nil {
		return nil, err
	}

	// No point in calculating policy if endpoint does not have an identity yet.
	if e.SecurityIdentity == nil {
		e.getLogger().Warn("Endpoint lacks identity, skipping policy calculation")
		e.runlock()
		return nil, nil
	}

	// Copy out some values we care about, then unlock
	forcePolicyCompute := e.forcePolicyCompute
	securityIdentity := e.SecurityIdentity

	// We are computing policy; set this to false.
	// We do this now, not in setDesiredPolicy(), because if another caller
	// comes in and forces computation, we should leave that for the *next*
	// regeneration.
	e.forcePolicyCompute = false

	result := &policyGenerateResult{
		selectorPolicy:   e.selectorPolicy,
		endpointPolicy:   e.desiredPolicy,
		identityRevision: e.identityRevision,
	}
	e.runlock()

	e.getLogger().Debug("Starting policy recalculation...")

	stats.waitingForPolicyRepository.Start()
	repo := e.policyGetter.GetPolicyRepository()
	repo.Mutex.RLock() // Be sure to release this lock!
	stats.waitingForPolicyRepository.End(true)

	result.policyRevision = repo.GetRevision()

	// Recompute policy for this endpoint only if not already done for this revision
	// and identity.
	if e.nextPolicyRevision >= result.policyRevision &&
		e.desiredPolicy != nil && result.selectorPolicy != nil {

		if !forcePolicyCompute {
			if logger := e.getLogger(); logging.CanLogAt(logger.Logger, logrus.DebugLevel) {
				e.getLogger().WithFields(logrus.Fields{
					"policyRevision.next": e.nextPolicyRevision,
					"policyRevision.repo": result.policyRevision,
					"policyChanged":       e.nextPolicyRevision > e.policyRevision,
				}).Debug("Skipping unnecessary endpoint policy recalculation")
			}
			repo.Mutex.RUnlock()
			return result, nil
		} else {
			e.getLogger().Debug("Forced policy recalculation")
		}
	}

	stats.policyCalculation.Start()
	defer func() { stats.policyCalculation.End(err == nil) }()
	if result.selectorPolicy == nil {
		// Upon initial insertion or restore, there's currently no good
		// trigger point to ensure that the security Identity is
		// assigned after the endpoint is added to the endpointmanager
		// (and hence also the identitymanager). In that case, detect
		// that the selectorPolicy is not set and find it.
		result.selectorPolicy = repo.GetPolicyCache().Lookup(securityIdentity)
		if result.selectorPolicy == nil {
			err := fmt.Errorf("no cached selectorPolicy found")
			e.getLogger().WithError(err).Warning("Failed to regenerate from cached policy")
			repo.Mutex.RUnlock()
			return result, err
		}
	}

	// UpdatePolicy ensures the SelectorPolicy is fully resolved.
	// Endpoint lock must not be held!
	// TODO: GH-7515: Consider ways to compute policy outside of the
	// endpoint regeneration process, ideally as part of the policy change
	// handler.
	err = repo.GetPolicyCache().UpdatePolicy(securityIdentity)
	if err != nil {
		e.getLogger().WithError(err).Warning("Failed to update policy")
		repo.Mutex.RUnlock()
		return nil, err
	}
	repo.Mutex.RUnlock() // Done with policy repository; release this now as Consume() can be slow

	// Consume converts a SelectorPolicy in to an EndpointPolicy
	result.endpointPolicy = result.selectorPolicy.Consume(e)
	return result, nil
}

// setDesiredPolicy updates the endpoint with the results of a policy calculation.
//
// The endpoint write lock must be held and not released until the desired policy has
// been pushed in to the policymaps via `syncPolicyMap`. This is so that we block
// ApplyPolicyMapChanges, which has the effect of blocking the ipcache from updating
// the ipcache bpf map. It is required that any pending changes are pushed in to
// the policymap before the ipcache map, otherwise endpoints could experience transient
// policy drops.
//
// Specifically, since policy is calculated asynchronously from the ipcacache's apply loop,
// it is probable that the new policy diverges from the bpf PolicyMap. So, we cannot safely
// consume incremental changes (and thus allow the ipcache to continue) until we have
// successfully performed a full sync with the endpoints PolicyMap. Otherwise,
// the ipcache may remove an identity from the ipcache that the bpf PolicyMap is still
// relying on.
func (e *Endpoint) setDesiredPolicy(res *policyGenerateResult) error {
	// nil result means endpoint had no identity while policy was calculated
	if res == nil {
		if e.SecurityIdentity != nil {
			e.getLogger().Info("Endpoint SecurityIdentity changed during policy regeneration")
			return fmt.Errorf("endpoint %d SecurityIdentity changed during policy regeneration", e.ID)
		}

		return nil
	}
	// if the security identity changed, reject the policy computation
	if e.identityRevision != res.identityRevision {
		e.getLogger().Info("Endpoint SecurityIdentity changed during policy regeneration")
		return fmt.Errorf("endpoint %d SecurityIdentity changed during policy regeneration", e.ID)
	}

	// Set the revision of this endpoint to the current revision of the policy
	// repository.
	e.setNextPolicyRevision(res.policyRevision)
	e.selectorPolicy = res.selectorPolicy
	e.desiredPolicy = res.endpointPolicy

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

	optsChanged = e.applyOptsLocked(opts)
	return
}

func (e *Endpoint) DumpLinks(tag string) {
	fmt.Println(e.ID, tag, "[tom-debug] #### tracing endpoint links ####")
	links, err := netlink.LinkList()
	if err != nil {
		fmt.Println(e.ID, tag, "[tom-debug] error listing links:", err)
		return
	}
	found := false
	for _, link := range links {
		if link.Attrs().Name == "lxc_health" {
			fmt.Println(e.ID, tag, "[tom-debug] link:", link.Attrs().Name, link.Attrs().Index)
			found = true
		}
	}
	if !found {
		fmt.Println(e.ID, "[tom-debug] Link not found here!!!! #######################")
	}
	fmt.Println(e.ID, tag, "[tom-debug] #### trace done ####")
}

// Called with e.mutex UNlocked
func (e *Endpoint) regenerate(ctx *regenerationContext) (retErr error) {
	var revision uint64
	var err error

	ctx.Stats = regenerationStatistics{}
	stats := &ctx.Stats
	stats.totalTime.Start()
	debugLogsEnabled := logging.CanLogAt(e.getLogger().Logger, logrus.DebugLevel)

	if debugLogsEnabled {
		e.getLogger().WithFields(logrus.Fields{
			logfields.StartTime: time.Now(),
			logfields.Reason:    ctx.Reason,
		}).Debug("Regenerating endpoint")
	}

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

	e.DumpLinks("regen [2]")

	// When building the initial drop policy in waiting-for-identity state
	// the state remains unchanged
	//
	// GH-5350: Remove this special case to require checking for StateWaitingForIdentity
	if e.getState() != StateWaitingForIdentity &&
		!e.BuilderSetStateLocked(StateRegenerating, "Regenerating endpoint: "+ctx.Reason) {
		e.DumpLinks("waiting for identity")
		if debugLogsEnabled {
			e.getLogger().WithField(logfields.EndpointState, e.state).Debug("Skipping build due to invalid state")
		}
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
		return fmt.Errorf("unable to remove old temporary directory: %w", err)
	}

	// Create temporary endpoint directory if it does not exist yet
	if err := os.MkdirAll(tmpDir, 0777); err != nil {
		stats.prepareBuild.End(false)
		return fmt.Errorf("Failed to create endpoint directory: %w", err)
	}
	e.DumpLinks("setup dirs done")

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

	revision, err = e.regenerateBPF(ctx)

	// Write full verifier log to the endpoint directory.
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		p := path.Join(tmpDir, "verifier.log")
		f, err := os.Create(p)
		if err != nil {
			return fmt.Errorf("creating endpoint verifier log file: %w", err)
		}
		defer f.Close()
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

	e.DumpLinks("about to realize")
	return e.updateRealizedState(stats, origDir, revision)
}

// updateRealizedState sets any realized state fields within the endpoint to
// be the desired state of the endpoint. This is only called after a successful
// regeneration of the endpoint.
func (e *Endpoint) updateRealizedState(stats *regenerationStatistics, origDir string, revision uint64) error {
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
	err = e.synchronizeDirectories(origDir)
	if err != nil {
		return fmt.Errorf("error synchronizing endpoint BPF program directories: %w", err)
	}

	// Start periodic background full reconciliation of the policy map.
	// Does nothing if it has already been started.
	if !e.isProperty(PropertyFakeEndpoint) &&
		option.Config.DatapathMode != datapathOption.DatapathModeLBOnly {
		e.startSyncPolicyMapController()
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

	e.DumpLinks("done realize")
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

	// Only add fields to the scoped logger if the criteria for logging a message is met, to avoid
	// the expensive call to 'WithFields'.
	scopedLog := e.getLogger()
	if err != nil || logging.CanLogAt(scopedLog.Logger, logrus.DebugLevel) {
		fields := logrus.Fields{
			logfields.Reason: ctx.Reason,
		}
		for field, stat := range stats.GetMap() {
			fields[field] = stat.Total()
		}
		for field, stat := range stats.datapathRealization.GetMap() {
			fields[field] = stat.Total()
		}
		scopedLog = scopedLog.WithFields(fields)
	}

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
	hr := e.GetReporter("datapath-regenerate")
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

		result, ok := <-resChan
		if ok {
			regenResult := result.(*EndpointRegenerationResult)
			regenError = regenResult.err
			buildSuccess = regenError == nil

			if regenError != nil && !errors.Is(regenError, context.Canceled) {
				e.getLogger().WithError(regenError).Error("endpoint regeneration failed")
				hr.Degraded("Endpoint regeneration failed", regenError)
			} else {
				hr.OK("Endpoint regeneration successful")
			}
		} else {
			// This may be unnecessary(?) since 'closing' of the results
			// channel means that event has been cancelled?
			e.getLogger().Debug("regeneration was cancelled")
			canceled = true
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
		Group: endpointRegenerationRecoveryControllerGroup,
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
				RegenerationLevel: regeneration.RegenerateWithDatapath,
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

	e.controllers.UpdateController(
		fmt.Sprintf("sync-%s-identity-mapping (%d)", addressFamily, e.ID),
		controller.ControllerParams{
			Group: syncAddressIdentityMappingControllerGroup,
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
				key := node.GetEndpointEncryptKeyIndex()
				metadata := e.FormatGlobalEndpointID()
				k8sNamespace := e.K8sNamespace
				k8sPodName := e.K8sPodName

				// Release lock as we do not want to have long-lasting key-value
				// store operations resulting in lock being held for a long time.
				e.runlock()

				if err := ipcache.UpsertIPToKVStore(ctx, endpointIP, hostIP, ID, key, metadata, k8sNamespace, k8sPodName, e.GetK8sPorts()); err != nil {
					return fmt.Errorf("unable to add endpoint IP mapping '%s'->'%d': %w", endpointIP.String(), ID, err)
				}
				return nil
			},
			StopFunc: func(ctx context.Context) error {
				ip := endpointIP.String()
				if err := ipcache.DeleteIPFromKVStore(ctx, ip); err != nil {
					return fmt.Errorf("unable to delete endpoint IP '%s' from ipcache: %w", ip, err)
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
	e.replaceIdentityLabels(labels.LabelSourceAny, identity.Labels)

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
func (e *Endpoint) UpdateBandwidthPolicy(bwm dptypes.BandwidthManager, annoCB AnnotationsResolverCB) {
	ch, err := e.eventQueue.Enqueue(eventqueue.NewEvent(&EndpointPolicyBandwidthEvent{
		bwm:    bwm,
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
func (e *Endpoint) GetRealizedPolicyRuleLabelsForKey(key policyTypes.Key) (
	derivedFrom labels.LabelArrayList,
	revision uint64,
	ok bool,
) {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	entry, ok := e.realizedPolicy.GetPolicyMap().Get(key)
	if !ok {
		return nil, 0, false
	}

	return entry.DerivedFromRules, e.policyRevision, true
}
