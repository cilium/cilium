// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/renameio/v2"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/loadinfo"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	policyapi "github.com/cilium/cilium/pkg/policy/api"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/cilium/pkg/version"
)

const (
	// EndpointGenerationTimeout specifies timeout for proxy completion context
	EndpointGenerationTimeout = 330 * time.Second

	// ciliumCHeaderPrefix is the prefix using when printing/writing an endpoint in a
	// base64 form.
	ciliumCHeaderPrefix = "CILIUM_BASE64_"
)

var (
	// ErrPolicyEntryMaxExceeded indicates that the BPF map backing the
	// endpoint policy is too full to accommodate a given set of changes.
	ErrPolicyEntryMaxExceeded = errors.New("policy map max entries limit exceeded")

	// ErrComingOutOfLockdown indicates that the BPF map backing the
	// endpoint policy is too full to accommodate a given set of changes.
	ErrComingOutOfLockdown = errors.New("lockdown is no longer needed, but a full policy recomputation is needed")

	handleNoHostInterfaceOnce sync.Once

	syncPolicymapControllerGroup = controller.NewGroup("sync-policymap")

	// allTrafficKeys specifies all of the policy Keys necessary to cover
	// all (ingress and egress) network traffic.
	allTrafficKeys []policy.Key
)

func init() {
	for _, proto := range policyapi.SupportedProtocols() {
		p := u8proto.ProtoIDs[strings.ToLower(string(proto))]
		allTrafficKeys = append(allTrafficKeys,
			policy.IngressKey().WithPortProtoPrefix(p, 0, 0),
			policy.EgressKey().WithPortProtoPrefix(p, 0, 0),
		)
	}
}

// callsMapPath returns the path to cilium tail calls map of an endpoint.
func (e *Endpoint) callsMapPath() string {
	return e.loader.CallsMapPath(e.ID)
}

// callsCustomMapPath returns the path to cilium custom tail calls map of an
// endpoint.
func (e *Endpoint) customCallsMapPath() string {
	return e.loader.CustomCallsMapPath(e.ID)
}

// writeInformationalComments writes annotations to the specified writer,
// including a base64 encoding of the endpoint object, and human-readable
// strings describing the configuration of the datapath.
//
// For configuration of actual datapath behavior, see WriteEndpointConfig().
//
// e.mutex must be RLock()ed
func (e *Endpoint) writeInformationalComments(w io.Writer) error {
	fw := bufio.NewWriter(w)

	fmt.Fprint(fw, "/*\n")
	fmt.Fprintln(fw, " * This file is not using during compilation of endpoint programs.")

	epStr64, err := e.base64()
	if err == nil {
		var verBase64 string
		verBase64, err = version.Base64()
		if err == nil {
			// Current versions ignore the comment, but we need to retain it
			// so that downgrades work.
			fmt.Fprintln(fw, " * The line below is retained for backwards compatibility only.")
			fmt.Fprintf(fw, " * %s%s:%s\n * \n", ciliumCHeaderPrefix,
				verBase64, epStr64)
		}
	}
	if err != nil {
		e.logStatusLocked(BPF, Warning, fmt.Sprintf("Unable to create a base64: %s", err))
	}

	if cid := e.GetContainerID(); cid == "" {
		fmt.Fprintf(fw, " * Docker Network ID: %s\n", e.dockerNetworkID)
		fmt.Fprintf(fw, " * Docker Endpoint ID: %s\n", e.dockerEndpointID)
	} else {
		fmt.Fprintf(fw, " * Container ID: %s\n", cid)
		fmt.Fprintf(fw, " * Container Interface: %s\n", e.containerIfName)
	}

	if e.parentIfIndex != 0 {
		fmt.Fprintf(fw, " * Parent Interface IfIndex: %d\n", e.parentIfIndex)
	}

	if option.Config.EnableIPv6 {
		fmt.Fprintf(fw, " * IPv6 address: %s\n", e.IPv6.String())
	}
	fmt.Fprintf(fw, ""+
		" * IPv4 address: %s\n"+
		" * Identity: %d\n"+
		" * PolicyMap: %s\n"+
		" * NodeMAC: %s\n"+
		" */\n\n",
		e.IPv4.String(),
		e.getIdentity(), bpf.LocalMapName(policymap.MapName, e.ID),
		e.nodeMAC)

	fw.WriteString("/*\n")
	fw.WriteString(" * Labels:\n")
	if e.SecurityIdentity != nil {
		if len(e.SecurityIdentity.Labels) == 0 {
			fmt.Fprintf(fw, " * - %s\n", "(no labels)")
		} else {
			for _, v := range e.SecurityIdentity.Labels {
				fmt.Fprintf(fw, " * - %s\n", v.String())
			}
		}
	}
	fw.WriteString(" */\n\n")

	return fw.Flush()
}

// writeHeaderfile writes the lxc_config.h header file of an endpoint.
//
// e.mutex must be write-locked.
func (e *Endpoint) writeHeaderfile(prefix string) error {
	headerPath := filepath.Join(prefix, common.CHeaderFileName)
	e.getLogger().Debug(
		"writing header file",
		logfields.Path, headerPath,
	)

	// Write state as a plain JSON.
	jsonState, err := e.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to serialize state: %w", err)
	}

	state, err := renameio.TempFile(prefix, filepath.Join(prefix, common.EndpointStateFileName))
	if err != nil {
		return fmt.Errorf("failed to open temporary file: %w", err)
	}
	defer state.Cleanup()

	if _, err := state.Write(jsonState); err != nil {
		return err
	}

	if err := state.CloseAtomicallyReplace(); err != nil {
		return err
	}

	f, err := renameio.TempFile(prefix, headerPath)
	if err != nil {
		return fmt.Errorf("failed to open temporary file: %w", err)
	}
	defer f.Cleanup()

	if e.DNSRulesV2 != nil {
		// Note: e.DNSRulesV2 is updated by syncEndpointHeaderFile and regenerateBPF
		// before they call into writeHeaderfile, because GetDNSRules must not be
		// called with endpoint.mutex held.
		e.getLogger().Debug(
			"writing header file with DNSRules",
			logfields.Path, headerPath,
			logfields.DNSRulesV2, e.DNSRulesV2,
		)
	}

	if err = e.writeInformationalComments(f); err != nil {
		return err
	}

	if err = e.orchestrator.WriteEndpointConfig(f, e); err != nil {
		return err
	}

	return f.CloseAtomicallyReplace()
}

// proxyPolicy implements policy.ProxyPolicy interface, and passes most of the calls
// to policy.L4Filter, but re-implements GetPort() to return the resolved named port,
// instead of returning a 0 port number.
type proxyPolicy struct {
	*policy.L4Filter
	l7Parser policy.L7ParserType
	listener string
	port     uint16
	protocol u8proto.U8proto
}

// newProxyPolicy returns a new instance of proxyPolicy by value
func newProxyPolicy(l4 *policy.L4Filter, l7Parser policy.L7ParserType, listener string, port uint16, proto u8proto.U8proto) proxyPolicy {
	return proxyPolicy{L4Filter: l4, l7Parser: l7Parser, listener: listener, port: port, protocol: proto}
}

func (p *proxyPolicy) GetL7Parser() policy.L7ParserType {
	return p.l7Parser
}

// GetPort returns the destination port number on which the proxy policy applies
// This version properly returns the port resolved from a named port, if any.
func (p *proxyPolicy) GetPort() uint16 {
	return p.port
}

// GetProtocol returns the destination protocol number on which the proxy policy applies
func (p *proxyPolicy) GetProtocol() u8proto.U8proto {
	return p.protocol
}

// GetListener returns the listener name referenced by the policy, if any
func (p *proxyPolicy) GetListener() string {
	return p.listener
}

// addNewRedirects must be called while holding the endpoint lock for reading.
// The returned map contains the exact set of IDs of proxy redirects that is
// required to implement the given L4 policy.
// Only called after a new selector policy has been computed.
func (e *Endpoint) addNewRedirects(selectorPolicy policy.SelectorPolicy, proxyWaitGroup *completion.WaitGroup) (desiredRedirects map[string]uint16, rf revert.RevertFunc) {
	if e.isProperty(PropertyFakeEndpoint) || e.IsProxyDisabled() {
		return nil, nil
	}

	desiredRedirects = make(map[string]uint16)

	var (
		revertStack  revert.RevertStack
		updatedStats []*models.ProxyStatistics
	)

	// create or update proxy redirects
	for l4, policySelectorTuple := range selectorPolicy.RedirectFilters() {
		// Possible listener name for both the proxy ID and the proxyPolicy below.
		listener := policySelectorTuple.Policy.GetListener()

		// proxyID() returns also the destination port for the policy,
		// which may be resolved from a named port
		proxyID, dstPort, dstProto := e.proxyID(l4, listener)
		if proxyID == "" {
			// Skip redirects for which a proxyID cannot be created.
			// This may happen due to the named port mapping not
			// existing or multiple PODs defining the same port name
			// with different port values. The redirect will be created
			// when the mapping is available or when the port name
			// conflicts have been resolved in POD specs.
			continue
		}
		// desiredRedirects starts out empty, so we can use it check
		// if the redirect has already been updated on this round.
		if desiredRedirects[proxyID] != 0 {
			continue
		}

		pp := newProxyPolicy(l4, policySelectorTuple.Policy.L7Parser, listener, dstPort, dstProto)
		proxyPort, err, revertFunc := e.proxy.CreateOrUpdateRedirect(e.aliveCtx, &pp, proxyID, e.ID, proxyWaitGroup)
		if err != nil {
			// Skip redirects that can not be created or updated.  This
			// can happen when a listener is missing, for example when
			// restarting and k8s delivers the CNP before the related
			// CEC.
			// Policy is regenerated when listeners are added or removed
			// to fix this condition when the listener is available.
			e.getLogger().Debug(
				"Redirect rule with missing listener skipped, will be applied once the listener is available",
				logfields.Error, err,
				logfields.Listener, pp.GetListener(),
			)
			continue
		}
		revertStack.Push(revertFunc)
		desiredRedirects[proxyID] = proxyPort

		// Update the endpoint API model to report that Cilium manages a
		// redirect for that port.
		statsKey := policy.ProxyStatsKey(l4.Ingress, string(l4.Protocol), dstPort, proxyPort)
		proxyStats := e.getProxyStatistics(statsKey, string(policySelectorTuple.Policy.L7Parser), dstPort, l4.Ingress, proxyPort)
		updatedStats = append(updatedStats, proxyStats)
	}

	// revert function is called with endpoint mutex held
	revertStack.Push(func() error {
		// Restore the proxy stats.
		e.proxyStatisticsMutex.Lock()
		for _, stats := range updatedStats {
			stats.AllocatedProxyPort = 0
		}
		e.proxyStatisticsMutex.Unlock()

		return nil
	})

	return desiredRedirects, revertStack.Revert
}

// Must be called with endpoint.mutex locked for writing, as this calls back to
// 'e.OnDNSPolicyUpdateLocked()'.
func (e *Endpoint) removeOldRedirects(desiredRedirects, realizedRedirects map[string]uint16) {
	if e.isProperty(PropertyFakeEndpoint) || e.IsProxyDisabled() {
		return
	}

	for id, redirectPort := range realizedRedirects {
		// Remove only the redirects that are not required.
		if desiredRedirects[id] != 0 {
			continue
		}

		if redirectPort != 0 {
			e.proxy.RemoveRedirect(id)
		}

		// Update the endpoint API model to report that no redirect is
		// active or known for that port anymore. We never delete stats
		// until an endpoint is deleted, so we only set the redirect port
		// to 0.
		_, ingress, protocol, port, _, _ := policy.ParseProxyID(id)
		key := policy.ProxyStatsKey(ingress, protocol, port, redirectPort)
		e.proxyStatisticsMutex.Lock()
		if proxyStats, ok := e.proxyStatistics[key]; ok {
			proxyStats.AllocatedProxyPort = 0
		} else {
			e.getLogger().Warn(
				"Proxy stats not found",
				logfields.L4PolicyID, id,
			)
		}
		e.proxyStatisticsMutex.Unlock()
	}
}

// regenerateBPF rewrites all headers and updates all BPF maps to reflect the
// specified endpoint.
// ReloadDatapath forces the datapath programs to be reloaded. It does
// not guarantee recompilation of the programs.
// Must be called with endpoint.mutex not held and endpoint.buildMutex held.
//
// Returns the policy revision number when the regeneration has called,
// Whether the new state dir is populated with all new BPF state files,
// and an error if something failed.
func (e *Endpoint) regenerateBPF(regenContext *regenerationContext) (revnum uint64, reterr error) {
	var err error

	stats := &regenContext.Stats
	stats.waitingForLock.Start()

	datapathRegenCtxt := regenContext.datapathRegenerationContext

	// Wait for the datapath to be initialized before we take the compilation read lock.
	// If we take the read lock before the datapath is initialized, we end up blocking
	// the datapath initialization which needs the write lock on `e.compilationLock`.
	// Yet, we will be blocked while waiting for the initialization to finish, thus causing
	// a deadlock.
	<-e.orchestrator.DatapathInitialized()

	// Make sure that owner is not compiling base programs while we are
	// regenerating an endpoint.
	e.compilationLock.RLock()
	stats.waitingForLock.End(true)
	defer e.compilationLock.RUnlock()

	if err := e.aliveCtx.Err(); err != nil {
		return 0, fmt.Errorf("endpoint was closed while waiting for datapath lock: %w", err)
	}

	datapathRegenCtxt.prepareForProxyUpdates(regenContext.parentContext)
	defer datapathRegenCtxt.completionCancel()

	err = e.runPreCompilationSteps(regenContext)
	// Keep track of the side-effects of the regeneration that need to be
	// reverted in case of failure.
	// Also keep track of the regeneration finalization code that can't be
	// reverted, and execute it in case of regeneration success.
	defer func() {
		// Ignore finalizing of proxy state in dry mode.
		if !e.isProperty(PropertyFakeEndpoint) {
			e.finalizeProxyState(regenContext, reterr)
		}
	}()

	if err != nil {
		return 0, err
	}

	// Avoid BPF program compilation and installation if the endpoint or node
	// configuration hasn't changed. Hashing the endpoint configuration requires
	// getting the security identity, which takes out a read lock on the Endpoint.
	// Make sure to calculate the endpoint hash outside of a locked context.
	datapathRegenCtxt.bpfHeaderfilesHash, err = e.orchestrator.EndpointHash(e)
	if err != nil {
		return 0, fmt.Errorf("hash endpoint configuration: %w", err)
	}

	if datapathRegenCtxt.bpfHeaderfilesHash != e.bpfHeaderfileHash {
		e.getLogger().Debug(
			"BPF endpoint configuration hashed",
			logfields.BPFHeaderfileHashOld, e.bpfHeaderfileHash,
			logfields.BPFHeaderfileHash, datapathRegenCtxt.bpfHeaderfilesHash,
		)

		datapathRegenCtxt.regenerationLevel = regeneration.RegenerateWithDatapath
	}

	if err := e.lockAlive(); err != nil {
		return 0, err
	}
	dir := datapathRegenCtxt.currentDir
	if datapathRegenCtxt.regenerationLevel >= regeneration.RegenerateWithDatapath {
		if err := e.writeHeaderfile(datapathRegenCtxt.nextDir); err != nil {
			return 0, fmt.Errorf("write endpoint header file: %w", err)
		}
		dir = datapathRegenCtxt.nextDir
	}
	datapathRegenCtxt.epInfoCache = e.createEpInfoCache(dir)
	e.unlock()

	// No need to compile BPF in dry mode. Also, in lb-only mode we do not
	// support local Pods on the worker node, hence endpoint BPF regeneration
	// is skipped everywhere.
	if e.isProperty(PropertyFakeEndpoint) {
		return e.nextPolicyRevision, nil
	}

	// Skip BPF if the endpoint has no policy map
	if e.isProperty(PropertySkipBPFPolicy) {
		// Ingress endpoint needs entries in the endpoints map so that the return traffic,
		// ARP, and IPv6 ND are delivered to the host stack in all datapath configurations.
		if e.isProperty(PropertyAtHostNS) {
			stats.mapSync.Start()
			err = lxcmap.WriteEndpoint(datapathRegenCtxt.epInfoCache)
			stats.mapSync.End(err == nil)
			if err != nil {
				return 0, fmt.Errorf("Exposing endpoint in endpoints BPF map failed: %w", err)
			}
		}

		// Allow another builder to start while we wait for the proxy
		if regenContext.DoneFunc != nil {
			regenContext.DoneFunc()
		}

		stats.proxyWaitForAck.Start()
		err = e.waitForProxyCompletions(datapathRegenCtxt.proxyWaitGroup)
		stats.proxyWaitForAck.End(err == nil)
		if err != nil {
			return 0, fmt.Errorf("Error while updating network policy: %w", err)
		}

		return e.nextPolicyRevision, nil
	}

	// Wait for connection tracking cleaning to complete
	stats.waitingForCTClean.Start()
	<-datapathRegenCtxt.ctCleaned
	stats.waitingForCTClean.End(true)

	err = e.realizeBPFState(regenContext)
	if err != nil {
		return datapathRegenCtxt.epInfoCache.revision, err
	}

	if !datapathRegenCtxt.epInfoCache.IsHost() || option.Config.EnableHostFirewall {
		// Hook the endpoint into the endpoint and endpoint to policy tables then expose it
		stats.mapSync.Start()
		err = lxcmap.WriteEndpoint(datapathRegenCtxt.epInfoCache)
		stats.mapSync.End(err == nil)
		if err != nil {
			return 0, fmt.Errorf("Exposing new BPF failed: %w", err)
		}
	}

	// Signal that BPF program has been generated.
	// The endpoint has at least L3/L4 connectivity at this point.
	e.closeBPFProgramChannel()

	// Allow another builder to start while we wait for the proxy
	if regenContext.DoneFunc != nil {
		regenContext.DoneFunc()
	}

	stats.proxyWaitForAck.Start()
	err = e.waitForProxyCompletions(datapathRegenCtxt.proxyWaitGroup)
	stats.proxyWaitForAck.End(err == nil)
	if err != nil {
		return 0, fmt.Errorf("error while configuring proxy redirects: %w", err)
	}

	stats.waitingForLock.Start()
	err = e.lockAlive()
	stats.waitingForLock.End(err == nil)
	if err != nil {
		return 0, err
	}
	defer e.unlock()

	e.ctCleaned = true

	if !datapathRegenCtxt.policyMapSyncDone {
		err = e.policyMapSync(datapathRegenCtxt.policyMapDump, stats)
		if err != nil {
			return 0, fmt.Errorf("unable to regenerate policy because PolicyMap synchronization failed: %w", err)
		}
		datapathRegenCtxt.policyMapSyncDone = true
	}

	// Initialize (if not done yet) the DNS history trigger to allow DNS proxy to trigger
	// updates to endpoint headers. The initialization happens here as at this point
	// datapath is ready to process the trigger.
	e.initDNSHistoryTrigger()

	return datapathRegenCtxt.epInfoCache.revision, err
}

// Synchronously try to update PolicyMap for this endpoint. If any
// part of updating the PolicyMap fails, bail out.
// Unfortunately, this means that the map will be in an inconsistent
// state with the current program (if it exists) for this endpoint.
// GH-3897 would fix this by creating a new map to do an atomic swap
// with the old one.
//
// This must be done after allocating the new redirects, to update the
// policy map with the new proxy ports.
//
// Sync is done against 'policyMapDump' if non-empty, otherwise it is done against e.realizedPolicy
// e.mutex must be held!
func (e *Endpoint) policyMapSync(policyMapDump policy.MapStateMap, stats *regenerationStatistics) (err error) {
	stats.mapSync.Start()
	// Nothing to do if the desired policy is already fully realized.
	if e.realizedPolicy != e.desiredPolicy {
		if len(policyMapDump) > 0 {
			_, _, err = e.syncPolicyMapWith(policyMapDump, false)
		} else {
			err = e.syncPolicyMap()
		}
	}
	stats.mapSync.End(err == nil)
	return err
}

func (e *Endpoint) realizeBPFState(regenContext *regenerationContext) (err error) {
	stats := &regenContext.Stats
	datapathRegenCtxt := regenContext.datapathRegenerationContext
	debugEnabled := e.getLogger().Enabled(context.Background(), slog.LevelDebug)

	if debugEnabled {
		e.getLogger().Debug(
			"Preparing to compile BPF",
			fieldRegenLevel, datapathRegenCtxt.regenerationLevel,
		)
	}

	if datapathRegenCtxt.regenerationLevel > regeneration.RegenerateWithoutDatapath {
		if debugEnabled {
			debugFunc := func(format string, args ...interface{}) {
				e.getLogger().Debug(fmt.Sprintf(format, args))
			}
			ctx, cancel := context.WithCancel(regenContext.parentContext)
			defer cancel()
			loadinfo.LogPeriodicSystemLoad(ctx, debugFunc, time.Second)
		}

		// Compile and install BPF programs for this endpoint
		templateHash, err := e.orchestrator.ReloadDatapath(datapathRegenCtxt.completionCtx, datapathRegenCtxt.epInfoCache, &stats.datapathRealization)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				e.getLogger().Error(
					"Error while reloading endpoint BPF program",
					logfields.Error, err,
				)
			}
			return err
		}

		if err := os.WriteFile(filepath.Join(datapathRegenCtxt.nextDir, defaults.TemplateIDPath), []byte(templateHash+"\n"), 0644); err != nil {
			return fmt.Errorf("unable to write template id: %w", err)
		}

		e.getLogger().Info("Reloaded endpoint BPF program")
		e.bpfHeaderfileHash = datapathRegenCtxt.bpfHeaderfilesHash
	} else if debugEnabled {
		e.getLogger().Debug(
			"BPF header file unchanged, skipping BPF compilation and installation",
			logfields.BPFHeaderfileHash, datapathRegenCtxt.bpfHeaderfilesHash,
		)
	}

	return nil
}

// runPreCompilationSteps runs all of the regeneration steps that are necessary
// right before compiling the BPF for the given endpoint.
// The endpoint mutex must not be held.
//
// Returns whether the headerfile changed and/or an error.
func (e *Endpoint) runPreCompilationSteps(regenContext *regenerationContext) (preCompilationError error) {
	stats := &regenContext.Stats
	datapathRegenCtxt := regenContext.datapathRegenerationContext

	// Signal computation of the initial Envoy policy even if we fail out so
	// that Envoy xDS server can start serving even if some endpoint
	// computations fail.
	defer func() {
		e.unconditionalLock()
		e.InitialPolicyComputedLocked()
		e.unlock()
	}()

	// lock the endpoint, read our values, then unlock
	err := e.lockAlive()
	if err != nil {
		return err
	}
	identityRevision := e.identityRevision
	e.unlock()
	policyRevision := e.policyRepo.GetRevision()

	// regenerate policy without holding the lock.
	// This is because policy generation needs the ipcache to make progress, and the ipcache
	// needs to call endpoint.ApplyPolicyMapChanges()
	// Computed only if not already done earlier, or if policy has updated since the policy was
	// computed.
	if datapathRegenCtxt.policyResult == nil ||
		datapathRegenCtxt.policyResult.endpointPolicy == nil ||
		datapathRegenCtxt.policyResult.identityRevision < identityRevision ||
		datapathRegenCtxt.policyResult.policyRevision < policyRevision {
		stats.policyCalculation.Start()
		err := e.regeneratePolicy(stats, datapathRegenCtxt)
		stats.policyCalculation.End(err == nil)
		if err != nil {
			return fmt.Errorf("unable to regenerate policy for '%s': %w", e.StringID(), err)
		}
	}

	// Once the policy has been calculated, we can update the standalone dns proxy as well.
	// We need to send the snapshot of the policyRules to SDP.
	if !e.isProperty(PropertyFakeEndpoint) && !e.IsProxyDisabled() {
		repo := e.policyRepo
		e.getLogger().Debug("Updating standalone DNS proxy with policy rules")
		policyRules := repo.GetPolicySnapshot()
		e.proxy.UpdateSDP(policyRules)
	}

	// Any possible DNS redirects had their rules updated by 'e.regeneratePolicy' above, so we
	// can get the new DNS rules for restoration now, before we take the endpoint lock below.
	// NOTE: Endpoint lock must not be held during 'GetDNSRules' as it locks IPCache, which
	// leads to a deadlock if endpoint lock is held.
	rules := e.dnsRulesAPI.GetDNSRules(e.ID)

	stats.waitingForLock.Start()
	err = e.lockAlive()
	stats.waitingForLock.End(err == nil)
	if err != nil {
		return err
	}

	defer e.unlock()

	// In the first ever regeneration of the endpoint, the conntrack table
	// is cleaned from the new endpoint IPs as it is guaranteed that any
	// pre-existing connections using that IP are now invalid.
	if !e.ctCleaned {
		go func() {
			if !e.isProperty(PropertyFakeEndpoint) {
				if ctmap.Exists(option.Config.EnableIPv4, option.Config.EnableIPv6) {
					e.scrubIPsInConntrackTable()
				}
			}
			close(datapathRegenCtxt.ctCleaned)
		}()
	} else {
		close(datapathRegenCtxt.ctCleaned)
	}

	// Set the computed policy as the "incoming" policy. This can fail if
	// the endpoint's security identity changed during or after policy calculation.
	// Note that the incoming policy can be the same as the previous policy in cases
	// where an unnecessary policy computation was skipped. In that case
	// e.desiredPolicy == e.realizedPolicy also after this call.
	if err := e.setDesiredPolicy(datapathRegenCtxt); err != nil {
		return err
	}
	// Mark the new desired policy as ready when done before the lock is released
	if e.desiredPolicy != e.realizedPolicy {
		defer e.desiredPolicy.Ready()
	}

	// Apply pending policy map changes so that desired map is up-to-date before
	// syncing the maps below.
	if e.SecurityIdentity != nil {
		_ = e.updateAndOverrideEndpointOptions(nil)

		// Apply incremental changes to desiredPolicy and Configure the new network policy
		// with the proxies.
		//
		// If we have a new policy, it is likely that incremental updates were applied to
		// the old policy while we were waiting for the endpoint lock. If we were to sync
		// policy maps without applying incremental updates first we could be flapping
		// network policy backwards just to be updating it again after applying incremental
		// updates later.
		//
		// This must be done after adding new redirects, as waiting for policy update
		// ACKs is disabled when there are no listeners, which is the case before the first
		// redirect is added.
		//
		// Do this before updating the bpf policy maps (later), so that the proxy listeners
		// have a chance to be ready when new traffic is redirected to them.  Note that it
		// is possible for further incremental changes to be applied before and after the
		// bpf policy maps have been synchronized for the new policy.
		err = e.applyPolicyMapChangesLocked(regenContext, e.desiredPolicy != e.realizedPolicy)
		if err != nil && !errors.Is(err, ErrPolicyEntryMaxExceeded) {
			return err
		}

		// Signal computation of the initial Envoy policy if not done yet
		e.InitialPolicyComputedLocked()
	}

	currentDir := datapathRegenCtxt.currentDir
	nextDir := datapathRegenCtxt.nextDir

	// We cannot obtain the rules while e.mutex is held, because obtaining
	// fresh DNSRules requires the IPCache lock (which must not be taken while
	// holding e.mutex to avoid deadlocks). Therefore, rules are obtained
	// before the call to runPreCompilationSteps.
	e.setDNSRulesLocked(rules)

	// If dry mode is enabled, no further changes to BPF maps are performed
	if e.isProperty(PropertySkipBPFPolicy) {
		// Ingress endpoint needs epInfoCache for endpointmap population
		if e.isProperty(PropertyAtHostNS) {
			datapathRegenCtxt.epInfoCache = e.createEpInfoCache(currentDir)
		}

		if e.isProperty(PropertyFakeEndpoint) {
			if err = e.writeHeaderfile(nextDir); err != nil {
				return fmt.Errorf("Unable to write header file: %w", err)
			}
		}
		return nil
	}

	if e.policyMap == nil {
		if e.policyMapFactory == nil {
			return fmt.Errorf("endpoint has nil policyMapFactory")
		}
		e.policyMap, err = e.policyMapFactory.OpenEndpoint(e.ID)
		if err != nil {
			return err
		}
	}

	// Collect a dump of the bpf policymap if needed for the sync.
	if e.realizedPolicy != e.desiredPolicy && e.realizedPolicy.Empty() {
		datapathRegenCtxt.policyMapDump, err = e.policyMap.DumpToMapStateMap()
		if err != nil {
			return fmt.Errorf("policymap dump failed: %w", err)
		}

		// Sync policy map before bpf compilation if the bpf policymap is empty.
		// This allows for upgrades and downgrades from versions using a different policy map
		if len(datapathRegenCtxt.policyMapDump) == 0 {
			err = e.policyMapSync(nil, stats)
			if err != nil {
				return fmt.Errorf("policymap synchronization failed: %w", err)
			}
		}
		datapathRegenCtxt.policyMapSyncDone = true
	}

	// sync policy map for fake endpoints, bpf compilation will be skipped for them.
	if e.isProperty(PropertyFakeEndpoint) {
		err = e.policyMapSync(nil, stats)
		if err != nil {
			return fmt.Errorf("fake ep policymap synchronization failed: %w", err)
		}
	}

	if e.isProperty(PropertySkipBPFRegeneration) {
		return nil
	}

	stats.prepareBuild.Start()
	defer func() {
		stats.prepareBuild.End(preCompilationError == nil)
	}()

	return nil
}

func (e *Endpoint) finalizeProxyState(regenContext *regenerationContext, err error) {
	datapathRegenCtx := regenContext.datapathRegenerationContext
	if err == nil {
		// Always execute the finalization code, even if the endpoint is
		// terminating, in order to properly release resources.
		e.unconditionalLock()
		defer e.unlock() // In case Finalize() panics
		e.getLogger().Debug("Finalizing successful endpoint regeneration")
		datapathRegenCtx.finalizeList.Finalize()
	} else {
		if err := e.lockAlive(); err != nil {
			e.getLogger().Debug(
				"Skipping unnecessary reverting of endpoint regeneration changes",
				logfields.Error, err,
			)
			return
		}
		defer e.unlock() // In case Revert() panics
		e.getLogger().Debug("Reverting endpoint changes after BPF regeneration failed")
		if err := datapathRegenCtx.revertStack.Revert(); err != nil {
			e.getLogger().Error(
				"Reverting endpoint regeneration changes failed",
				logfields.Error, err,
			)
		}
		e.getLogger().Debug("Finished reverting endpoint changes after BPF regeneration failed")
	}
}

// InitMap creates the policy map in the kernel.
func (e *Endpoint) InitMap() error {
	if e.policyMapFactory == nil {
		return fmt.Errorf("endpoint has nil policyMapFactory")
	}
	return e.policyMapFactory.CreateEndpoint(e.ID)
}

// deleteMaps deletes the endpoint's entry from the global
// cilium_(egress)call_policy maps and removes endpoint-specific cilium_calls_,
// cilium_policy_v2_ and cilium_ct{4,6}_ map pins.
//
// Call this after the endpoint's tc hook has been detached.
func (e *Endpoint) deleteMaps() []error {
	var errors []error

	// Remove the endpoint from cilium_lxc. After this point, ip->epID lookups
	// will fail, causing packets to/from the Pod to be dropped in many cases,
	// stopping packet evaluation.
	if err := lxcmap.DeleteElement(logging.DefaultSlogLogger, e); err != nil {
		errors = append(errors, err...)
	}

	// Remove the policy tail call entry for the endpoint. This will disable
	// policy evaluation for the endpoint and will result in missing tail calls if
	// e.g. bpf_host or bpf_overlay call into the endpoint's policy program.
	if err := policymap.RemoveGlobalMapping(logging.DefaultSlogLogger, uint32(e.ID)); err != nil {
		errors = append(errors, fmt.Errorf("removing endpoint program from global policy map: %w", err))
	}

	// Remove rate limit from bandwidth manager map.
	if e.bps != 0 {
		e.bandwidthManager.DeleteBandwidthLimit(e.ID)
	}
	if e.ingressBps != 0 {
		e.bandwidthManager.DeleteIngressBandwidthLimit(e.ID)
	}

	// Remove program array pins as the last step. This permanently invalidates
	// the endpoint programs' state, because removing a program array map pin
	// removes the map's entries even if the map is still referenced by any live
	// bpf programs, potentially resulting in missed tail calls if any packets are
	// still in flight.
	if e.policyMapFactory != nil {
		if err := e.policyMapFactory.RemoveEndpoint(e.ID); err != nil {
			errors = append(errors, fmt.Errorf("removing policy map pin for endpoint %s: %w", e.StringID(), err))
		}
	}
	if err := os.RemoveAll(e.callsMapPath()); err != nil {
		errors = append(errors, fmt.Errorf("removing calls map pin for endpoint %s: %w", e.StringID(), err))
	}
	if !e.isHost {
		if err := os.RemoveAll(e.customCallsMapPath()); err != nil {
			errors = append(errors, fmt.Errorf("removing custom calls map pin for endpoint %s: %w", e.StringID(), err))
		}
	}

	return errors
}

// garbageCollectConntrack will run the ctmap.GC() on either the endpoint's
// local conntrack table or the global conntrack table.
//
// The endpoint lock must be held
func (e *Endpoint) garbageCollectConntrack(filter ctmap.GCFilter) {
	for _, m := range ctmap.GlobalMaps(option.Config.EnableIPv4, option.Config.EnableIPv6) {
		if err := m.Open(); err != nil {
			// If the CT table doesn't exist, there's nothing to GC.
			if os.IsNotExist(err) {
				e.getLogger().Debug(
					"Skipping GC for endpoint",
					logfields.Error, err,
				)
			} else {
				e.getLogger().Warn(
					"Unable to open map",
					logfields.Error, err,
				)
			}
			continue
		}
		defer m.Close()

		e.ctMapGC.Run(m, filter)
	}
}

func (e *Endpoint) scrubIPsInConntrackTableLocked() {
	e.garbageCollectConntrack(ctmap.GCFilter{
		MatchIPs: map[netip.Addr]struct{}{
			e.IPv4: {},
			e.IPv6: {},
		},
	})
}

func (e *Endpoint) scrubIPsInConntrackTable() {
	e.unconditionalLock()
	e.scrubIPsInConntrackTableLocked()
	e.unlock()
}

// SkipStateClean can be called on a endpoint before its first build to skip
// the cleaning of state such as the conntrack table. This is useful when an
// endpoint is being restored from state and the datapath state should not be
// cleaned.
//
// The endpoint lock must NOT be held.
func (e *Endpoint) SkipStateClean() {
	// Mark conntrack as already cleaned
	e.unconditionalLock()
	e.ctCleaned = true
	e.unlock()
}

// PolicyMapPressureEvent represents an event for a policymap pressure metric
// update that is sent via the policyMapPressureUpdater interface.
type PolicyMapPressureEvent struct {
	Value      float64
	EndpointID uint16
}

type policyMapPressureUpdater interface {
	Update(PolicyMapPressureEvent)
	Remove(uint16)
}

func (e *Endpoint) updatePolicyMapPressureMetric(add float64) {
	// We want to use desiredPolicy, but it can be nil.
	policyLen := add
	if e.desiredPolicy != nil {
		policyLen += float64(e.desiredPolicy.Len())
	}
	value := policyLen / float64(e.policyMap.MaxEntries())
	e.PolicyMapPressureUpdater.Update(PolicyMapPressureEvent{
		Value:      value,
		EndpointID: e.ID,
	})
}

func (e *Endpoint) deletePolicyKeys(deletes, adds policy.Keys) int {
	var errors int
	for k := range deletes {
		if _, ok := adds[k]; !ok {
			if !e.deletePolicyKey(k) {
				errors++
			}
		}
	}
	return errors
}

func (e *Endpoint) deletePolicyKey(keyToDelete policy.Key) bool {
	policymapKey := policymap.NewKeyFromPolicyKey(keyToDelete)

	// Do not error out if the map entry was already deleted from the bpf map.
	// Incremental updates depend on this being OK in cases where identity change
	// events overlap with full policy computation.
	// In other cases we only delete entries that exist, but even in that case it
	// is better to not error out if somebody else has deleted the map entry in the
	// meanwhile.
	err := e.policyMap.DeleteKey(policymapKey)
	var errno unix.Errno
	errors.As(err, &errno)
	if err != nil && errno != unix.ENOENT {
		e.getLogger().Error(
			"Failed to delete PolicyMap key",
			logfields.Error, err,
			logfields.BPFMapKey, policymapKey,
		)
		return false
	}

	e.updatePolicyMapPressureMetric(0)

	e.PolicyDebug(
		"deletePolicyKey",
		logfields.BPFMapKey, keyToDelete,
	)

	return true
}

func (e *Endpoint) addPolicyKeys(adds policy.Keys) int {
	var errors int
	for keyToAdd := range adds {
		entry, exists := e.desiredPolicy.Get(keyToAdd)
		if !exists {
			e.getLogger().Warn(
				"Tried adding policy map key not in policy",
				logfields.AddedPolicyID, keyToAdd,
			)
			continue
		}

		if !e.addPolicyKey(keyToAdd, entry) {
			errors++
		}

	}
	return errors
}

func (e *Endpoint) addPolicyKey(keyToAdd policy.Key, entry policy.MapStateEntry) bool {
	// Convert from policy.Key to policymap.PolicyKey and Entry, respectively
	policymapKey := policymap.NewKeyFromPolicyKey(keyToAdd)
	policymapEntry := policymap.NewEntryFromPolicyEntry(policymapKey, entry)

	err := e.policyMap.Update(&policymapKey, &policymapEntry)
	if err != nil {
		e.getLogger().Error(
			"Failed to add PolicyMap key",
			logfields.Error, err,
			logfields.BPFMapKey, policymapKey,
			logfields.Port, entry.ProxyPort,
		)
		return false
	}

	e.updatePolicyMapPressureMetric(0)

	e.PolicyDebug(
		"addPolicyKey",
		logfields.BPFMapKey, keyToAdd,
		logfields.BPFMapValue, entry,
	)
	return true
}

// ApplyPolicyMapChanges updates the Endpoint's PolicyMap with the changes
// that have accumulated for the PolicyMap via various outside events (e.g.,
// identities added / deleted).
// 'proxyWaitGroup' may not be nil.
func (e *Endpoint) ApplyPolicyMapChanges(proxyWaitGroup *completion.WaitGroup) error {
	if err := e.lockAlive(); err != nil {
		return err
	}
	defer e.unlock()

	e.PolicyDebug("ApplyPolicyMapChanges")

	return e.applyPolicyMapChangesLocked(&regenerationContext{
		datapathRegenerationContext: &datapathRegenerationContext{
			proxyWaitGroup: proxyWaitGroup,
		},
	}, false)
}

// applyPolicyMapChangesLocked applies any incremental policy map changes
// collected on the desired policy. Endpoint's Envoy NetworkPolicy is also
// updated if needed. Endpoint must be locked. It returns one special error
// that must be considered, "ErrPolicyEntryMaxExceeded".
func (e *Endpoint) applyPolicyMapChangesLocked(regenContext *regenerationContext, hasNewPolicy bool) error {
	e.PolicyDebug("applyPolicyMapChanges")

	// Always update Envoy if policy has changed
	updateEnvoy := hasNewPolicy

	// Note that after successful endpoint regeneration the desired and realized policies are
	// the same pointer. During the bpf regeneration possible incremental updates are collected
	// on the newly computed desired policy, which is not fully realized yet. This is why we get
	// the map changes from the desired policy here.

	// ConsumeMapChanges() applies the incremental updates to the desired policy and only
	// returns changes that need to be applied to the Endpoint's bpf policy map.
	closer, changes := e.desiredPolicy.ConsumeMapChanges()
	defer closer()

	changeSize := changes.Size()
	if e.shouldLockdownLocked(changeSize) {
		return e.startLockdownLocked(changeSize)
	}
	if e.stopLockdownLocked() {
		return ErrComingOutOfLockdown
	}

	hasEnvoyRedirect := e.desiredPolicy.L4Policy.HasEnvoyRedirect()
	if !changes.Empty() {
		// updateEnvoy if there were any mapChanges, but only if the endpoint has Envoy
		// redirects, or is an Ingress endpoint, which needs to enforce also the full L3/4
		// policy.
		//
		// Even if there are no changes, we update the proxyWaitGroup for any in-progress
		// NetworkPolicy update to be done if the endpoint has envoy redirects, so that the
		// the expected policy is in place.
		//
		// 'updateEnvoy' is already set to 'true' if policy changed. In that case there can
		// be new redirects and a full policy map update even if there were no incremental
		// updates.
		updateEnvoy = updateEnvoy || hasEnvoyRedirect || e.isIngress
	}

	stats := &regenContext.Stats
	datapathRegenCtxt := regenContext.datapathRegenerationContext
	var err error

	proxyWaitGroup := datapathRegenCtxt.proxyWaitGroup

	// Ingress endpoint does not need to wait.
	// This also lets daemon/cmd integration tests to proceed
	if e.isProperty(PropertySkipBPFPolicy) {
		e.getLogger().Debug(
			"Ingress Endpoint updating Network policy",
		)
		proxyWaitGroup = nil
	}

	// Configure the new network policy with the proxies.
	//
	// This must be done after adding new redirects, as waiting for policy update ACKs is
	// disabled when there are no listeners, which is the case before the first redirect is
	// added.
	//
	// Do this before updating the bpf policy maps below, so that the proxy listeners have a
	// chance to be ready when new traffic is redirected to them.
	// NOTE: unlike regeneratePolicy, UpdateNetworkPolicy requires the endpoint read lock for
	// 'e.desiredPolicy' access.
	if !e.IsProxyDisabled() {
		if updateEnvoy {
			e.getLogger().Debug(
				"applyPolicyMapChanges: Updating Envoy NetworkPolicy",
				logfields.SelectorCacheVersion, e.desiredPolicy.VersionHandle,
			)
			stats.proxyPolicyCalculation.Start()
			var rf revert.RevertFunc
			err, rf = e.proxy.UpdateNetworkPolicy(e, &e.desiredPolicy.L4Policy, e.desiredPolicy.IngressPolicyEnabled, e.desiredPolicy.EgressPolicyEnabled, proxyWaitGroup)
			stats.proxyPolicyCalculation.End(err == nil)
			if err == nil {
				datapathRegenCtxt.revertStack.Push(rf)
			}
		} else if hasEnvoyRedirect {
			// Wait for a possible ongoing update to be done if there were no current changes.
			e.getLogger().Debug(
				"applyPolicyMapChanges: Using current Networkpolicy",
				logfields.SelectorCacheVersion, e.desiredPolicy.VersionHandle,
			)
			e.proxy.UseCurrentNetworkPolicy(e, &e.desiredPolicy.L4Policy, proxyWaitGroup)
		}
	}

	// Ingress endpoint has no bpf policy maps, so return before applying changes to bpf.
	if e.isProperty(PropertySkipBPFPolicy) {
		e.getLogger().Debug(
			"Skipping bpf updates due to dry mode",
		)
		return nil
	}

	if hasNewPolicy {
		// A full bpf map sync will be done for a new policy after proxy has ACKed the
		// redirects and network policy.
		return nil
	}

	if e.policyMap == nil {
		e.getLogger().Debug("Skipping bpf updates due to endpoint not having policy map yet")
		return nil
	}

	// Add policy map entries before deleting to avoid transient drops. If there
	// isn't enough space to add all the entries before deleting some, then delete
	// first. If e.realizedPolicy or e.policyMap is nil then the map has not been
	// populated yet.
	errors := 0
	if e.realizedPolicy == nil ||
		e.realizedPolicy.Len()+len(changes.Adds) <= int(e.policyMap.MaxEntries()) {
		errors += e.addPolicyKeys(changes.Adds)
		errors += e.deletePolicyKeys(changes.Deletes, changes.Adds)
	} else {
		errors += e.deletePolicyKeys(changes.Deletes, changes.Adds)
		errors += e.addPolicyKeys(changes.Adds)
		e.getLogger().Warn(
			"A policy map update had to delete changes before it added them in order to prevent a map overflow, a transient drop may have occurred.",
		)
	}

	if errors > 0 {
		return fmt.Errorf("updating bpf policy maps failed")
	}
	if len(changes.Adds) > 0 || len(changes.Deletes) > 0 {
		e.getLogger().Debug(
			"Applied policy map updates due to identity changes",
			logfields.AddedPolicyID, changes.Adds,
			logfields.DeletedPolicyID, changes.Deletes,
		)
	}
	return nil
}

// shouldLockdownLockdown returns true if the desiredPolicy, after changes,
// will be larger than policymap.MaxEntries. The Endpoint must be locked.
func (e *Endpoint) shouldLockdownLocked(changeSize int) bool {
	// The desiredPolicy will be larger than the BPF maximum after
	// the changes.
	return e.desiredPolicy != nil && e.policyMap != nil &&
		e.desiredPolicy.Len()+changeSize > int(e.policyMap.MaxEntries())
}

// startLockdownLocked initiates an endpoint lockdown, and returns an
// error if it fails. The Endpoint must be locked.
func (e *Endpoint) startLockdownLocked(changeSize int) error {
	// We only need to go through the mechanics of
	// lockdown once.
	if !e.lockdown {
		// Do nothing if lockdown mode is not enabled.
		if !option.Config.EnableEndpointLockdownOnPolicyOverflow {
			return nil
		}

		e.getLogger().Warn(
			fmt.Sprintf("The policy map exceeds the max entries limit, %s is enabled, locking the endpoint down.",
				option.EnableEndpointLockdownOnPolicyOverflow),
		)

		if err := e.endpointPolicyLockdown(); err != nil {
			e.getLogger().Error(
				"Failed to lockdown endpoint:"+
					"Consider quarantining or shutting down this node.",
				logfields.Error, err,
			)
			return err
		}
		e.lockdown = true
		e.updatePolicyMapPressureMetric(float64(changeSize))
	}
	return ErrPolicyEntryMaxExceeded
}

// stopLockdownLocked stops an endpoint lockdown if the endpoint
// is in lockdown. It returns true if it did stop a lockdown and
// false if it did not.
func (e *Endpoint) stopLockdownLocked() bool {
	if e.lockdown {
		e.forcePolicyCompute = true
		e.lockdown = false
		return true
	}
	return false
}

// endpointPolicyLockdown puts the endpoint policy map into a lockdown
// mode. The bpf policy map is populated with deny all traffic entries,
// and all other entries are deleted.
func (e *Endpoint) endpointPolicyLockdown() error {
	denyMap := make(map[policymap.PolicyKey]policymap.PolicyEntry, len(allTrafficKeys))
	for _, k := range allTrafficKeys {
		mk := policymap.NewKeyFromPolicyKey(k)
		denyMap[mk] = policymap.NewEntryFromPolicyEntry(mk, policytypes.DenyEntry())
	}
	// realizedPolicy is not accurrate at this point, we need a dump
	currentMap, err := e.policyMap.DumpToMapStateMap()
	if err != nil {
		return fmt.Errorf("could not dump current map state: %w", err)
	}

	defer func() {
		e.realizedPolicy = policy.NewEndpointPolicy(logging.DefaultSlogLogger, e.policyRepo)
	}()

	i := 0
	addedDenyEntries := false
	for k := range currentMap {
		pmKey := policymap.NewKeyFromPolicyKey(k)
		if _, ok := denyMap[pmKey]; !ok {
			err := e.policyMap.DeleteKey(pmKey)
			var errno unix.Errno
			errors.As(err, &errno)
			if err != nil && errno != unix.ENOENT {
				return fmt.Errorf("failed to delete policy key (%v) during lockdown: %w", pmKey, err)
			}
		}
		// We can increment this, even if we did not delete a key,
		// because non-deleted keys match what is already in the
		// deny map, they will be replaced.
		i++
		// Once the length of the deny keys to be added has been deleted we can safely add them.
		if i == len(denyMap) {
			for mk, mv := range denyMap {
				if err := e.policyMap.Update(&mk, &mv); err != nil {
					return fmt.Errorf("failed to add deny all policy (%v): %w", mv, err)
				}
			}
			addedDenyEntries = true
		}
	}
	// This is not really possible, unless the max policy limit
	// is set to a really low value in a custom build of Cilium,
	// but it is worth having for testing purposes.
	if !addedDenyEntries {
		for mk, mv := range denyMap {
			if err := e.policyMap.Update(&mk, &mv); err != nil {
				return fmt.Errorf("failed to add deny all policy (%v): %w", mk, err)
			}
		}
	}
	return nil
}

// syncPolicyMap updates the bpf policy map state based on the
// difference between the realized and desired policy state without
// dumping the bpf policy map.
// Only called when desired and realized policies are not the same.
func (e *Endpoint) syncPolicyMap() error {
	addErrors, deleteErrors := 0, 0

	if e.shouldLockdownLocked(0) {
		return e.startLockdownLocked(0)
	}
	if e.stopLockdownLocked() {
		return ErrComingOutOfLockdown
	}

	// Add policy map entries before deleting to avoid transient drops
	for k, v := range e.desiredPolicy.Updated(e.realizedPolicy) {
		if !e.addPolicyKey(k, v) {
			addErrors++
		}
	}

	// Delete policy keys present in the realized state, but not present in the desired state
	for k := range e.desiredPolicy.Missing(e.realizedPolicy) {
		if !e.deletePolicyKey(k) {
			deleteErrors++
		}
	}

	// Retry adds after deletes. If policy map became full, there might be some space if any
	// keys were deleted
	if addErrors > 0 {
		addErrors = 0
		// Add policy map entries before deleting to avoid transient drops
		for k, v := range e.desiredPolicy.Updated(e.realizedPolicy) {
			if !e.addPolicyKey(k, v) {
				addErrors++
			}
		}
	}

	if addErrors > 0 || deleteErrors > 0 {
		return fmt.Errorf("syncRealizedPolicyMap failed")
	}
	return nil
}

// syncPolicyMapWith updates the bpf policy map state based on the
// difference between a realized MapStateMap from a recent policy map dump
// and desired policy state.
func (e *Endpoint) syncPolicyMapWith(realized policy.MapStateMap, withDiffs bool) (diffCount int, diffs []policy.MapChange, err error) {
	addErrors, deleteErrors := 0, 0

	if e.shouldLockdownLocked(0) {
		err = e.startLockdownLocked(0)
		return
	}
	if e.stopLockdownLocked() {
		err = ErrComingOutOfLockdown
		return
	}

	// Add policy map entries before deleting to avoid transient drops
	for k, v := range e.desiredPolicy.UpdatedMap(realized) {
		if !e.addPolicyKey(k, v) {
			addErrors++
			continue
		}
		diffCount++
		if withDiffs {
			diffs = append(diffs, policy.MapChange{
				Add:   true,
				Key:   k,
				Value: v,
			})
		}
	}
	if addErrors > 0 {
		// Retrying adds below, so clear collected state
		diffCount = 0
		if withDiffs {
			diffs = diffs[:0]
		}
	}

	// Delete policy keys present in the realized state, but not present in the desired state
	for k, v := range e.desiredPolicy.MissingMap(realized) {
		if !e.deletePolicyKey(k) {
			deleteErrors++
			continue
		}
		diffCount++
		if withDiffs {
			diffs = append(diffs, policy.MapChange{
				Key:   k,
				Value: v,
			})
		}
	}

	// Retry adds after deletes. If policy map became full, there might be some space if any
	// keys were deleted
	if addErrors > 0 {
		addErrors = 0
		for k, v := range e.desiredPolicy.UpdatedMap(realized) {
			if !e.addPolicyKey(k, v) {
				addErrors++
				continue
			}
			diffCount++
			if withDiffs {
				diffs = append(diffs, policy.MapChange{
					Add:   true,
					Key:   k,
					Value: v,
				})
			}
		}
	}

	if addErrors > 0 || deleteErrors > 0 {
		err = fmt.Errorf("syncPolicyMapWith failed")
	}
	return diffCount, diffs, err
}

// syncPolicyMapWithDump is invoked periodically to perform a full reconciliation
// of the endpoint's PolicyMap against the BPF maps to catch cases where either
// due to kernel issue or user intervention the agent's view of the PolicyMap
// state has diverged from the kernel. A warning is logged if this method finds
// such an discrepancy.
//
// Returns an error if the endpoint's BPF PolicyMap is unable to be dumped,
// or any update operation to the map fails.
// Must be called with e.mutex Lock()ed.
func (e *Endpoint) syncPolicyMapWithDump() error {
	if e.policyMap == nil {
		return fmt.Errorf("not syncing PolicyMap state for endpoint because PolicyMap is nil")
	}

	// Endpoint not yet fully initialized or currently regenerating. Skip the check
	// this round.
	if e.getState() != StateReady {
		return nil
	}

	currentMap, err := e.policyMap.DumpToMapStateMap()
	// If map is unable to be dumped, attempt to close map and open it again.
	// See GH-4229.
	if err != nil {
		e.getLogger().Error("unable to dump PolicyMap when trying to sync desired and realized PolicyMap state", logfields.Error, err)

		// Close to avoid leaking of file descriptors, but still continue in case
		// Close() does not succeed, because otherwise the map will never be
		// opened again unless the agent is restarted.
		err := e.policyMap.Close()
		if err != nil {
			e.getLogger().Error("unable to close PolicyMap which was not able to be dumped", logfields.Error, err)
		}

		if e.policyMapFactory == nil {
			return fmt.Errorf("endpoint has nil policyMapFactory")
		}
		e.policyMap, err = e.policyMapFactory.OpenEndpoint(e.ID)
		if err != nil {
			return fmt.Errorf("unable to open PolicyMap for endpoint: %w", err)
		}

		// Try to dump again, fail if error occurs.
		currentMap, err = e.policyMap.DumpToMapStateMap()
		if err != nil {
			return err
		}
	}

	// Log full policy map for every dump
	e.PolicyDebug("syncPolicyMapWithDump", logfields.DumpedPolicyMap, currentMap)
	// Diffs between the maps indicate an error in the policy map update logic.
	// Collect and log diffs if policy logging is enabled.
	diffCount, diffs, err := e.syncPolicyMapWith(currentMap, e.getPolicyLogger() != nil)

	if diffCount > 0 {
		e.getLogger().Warn("Policy map sync fixed errors, consider running with debug verbose = policy to get detailed dumps", logfields.Count, diffCount)
		e.PolicyDebug("syncPolicyMapWithDump", logfields.DumpedDiffs, diffs)
	}

	return err
}

func (e *Endpoint) startSyncPolicyMapController() {
	// Skip the controller if the endpoint has no policy map
	if e.isProperty(PropertySkipBPFPolicy) {
		return
	}

	ctrlName := fmt.Sprintf("sync-policymap-%d", e.ID)
	e.controllers.CreateController(ctrlName,
		controller.ControllerParams{
			Group:  syncPolicymapControllerGroup,
			Health: e.GetReporter("policymap-sync"),
			DoFunc: func(ctx context.Context) error {
				// Failure to lock is not an error, it means
				// that the endpoint was disconnected and we
				// should exit gracefully.
				if err := e.lockAlive(); err != nil {
					return controller.NewExitReason("Endpoint disappeared")
				}
				defer e.unlock()
				if e.desiredPolicy != e.realizedPolicy {
					// Currently in the middle of a regeneration; do not execute
					// at this time.
					return nil
				}
				return e.syncPolicyMapWithDump()
			},
			RunInterval: option.Config.PolicyMapFullReconciliationInterval,
			Context:     e.aliveCtx,
		},
	)
}

// RequireARPPassthrough returns true if the datapath must implement ARP
// passthrough for this endpoint
func (e *Endpoint) RequireARPPassthrough() bool {
	return e.DatapathConfiguration.RequireArpPassthrough
}

// RequireEgressProg returns true if the endpoint requires bpf_lxc with section
// "to-container" to be attached at egress on the host facing veth pair
func (e *Endpoint) RequireEgressProg() bool {
	return e.DatapathConfiguration.RequireEgressProg
}

// RequireRouting returns true if the endpoint requires BPF routing to be
// enabled, when disabled, routing is delegated to Linux routing
func (e *Endpoint) RequireRouting() (required bool) {
	required = true
	if e.DatapathConfiguration.RequireRouting != nil {
		required = *e.DatapathConfiguration.RequireRouting
	}
	return
}

// RequireEndpointRoute returns if the endpoint wants a per endpoint route
func (e *Endpoint) RequireEndpointRoute() bool {
	return e.DatapathConfiguration.InstallEndpointRoute
}

// GetPolicyVerdictLogFilter returns the PolicyVerdictLogFilter that would control
// the creation of policy verdict logs. Value of VerdictLogFilter needs to be
// consistent with how it is used in policy_verdict_filter_allow() in bpf/lib/policy_log.h
func (e *Endpoint) GetPolicyVerdictLogFilter() uint32 {
	var filter uint32 = 0
	if e.desiredPolicy.IngressPolicyEnabled {
		filter = (filter | 0x1)
	}
	if e.desiredPolicy.EgressPolicyEnabled {
		filter = (filter | 0x2)
	}
	return filter
}

type linkCheckerFunc func(string) error

// ValidateConnectorPlumbing checks whether the endpoint is correctly plumbed.
func (e *Endpoint) ValidateConnectorPlumbing(linkChecker linkCheckerFunc) error {
	if linkChecker == nil {
		return fmt.Errorf("cannot check state of datapath; link checker is nil")
	}
	err := linkChecker(e.ifName)
	if err != nil {
		return fmt.Errorf("interface %s could not be found", e.ifName)
	}
	return nil
}

// CheckHealth verifies that the endpoint is alive and healthy by checking the
// link status. This satisfies endpointmanager.EndpointCheckerFunc.
func CheckHealth(ep *Endpoint) error {
	// Be extra careful, we're only looking for one specific type of error
	// currently: That the link has gone missing. Ignore other error to
	// ensure that the caller doesn't unintentionally tear down the
	// Endpoint thinking that it no longer exists.
	iface := ep.HostInterface()
	if iface == "" {
		handleNoHostInterfaceOnce.Do(func() {
			ep.getLogger().Info(
				"Endpoint garbage collection is ineffective, ignoring endpoint",
				logfields.URL, "https://github.com/cilium/cilium/pull/14541",
				logfields.HelpMessage, "For more information, see the linked URL. Pass endpoint-gc-interval=\"0\" to disable",
			)
		})
		return nil
	}
	_, err := safenetlink.LinkByName(iface)
	var linkNotFoundError netlink.LinkNotFoundError
	if errors.As(err, &linkNotFoundError) {
		return fmt.Errorf("Endpoint is invalid: %w", err)
	}
	if err != nil {
		ep.getLogger().Warn(
			"An error occurred while checking endpoint health",
			logfields.Error, err,
		)
	}
	return nil
}
