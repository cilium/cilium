// Copyright 2016-2021 Authors of Cilium
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
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadinfo"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/bwmap"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/eppolicymap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/version"

	"github.com/google/renameio"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// EndpointGenerationTimeout specifies timeout for proxy completion context
	EndpointGenerationTimeout = 330 * time.Second

	// OldCHeaderFileName is the previous name of the C header file for BPF
	// programs for a particular endpoint. It can be removed once Cilium v1.8
	// is the oldest supported version.
	oldCHeaderFileName = "lxc_config.h"

	// ciliumCHeaderPrefix is the prefix using when printing/writing an endpoint in a
	// base64 form.
	ciliumCHeaderPrefix = "CILIUM_BASE64_"
)

var (
	handleNoHostInterfaceOnce sync.Once
)

// policyMapPath returns the path to the policy map of endpoint.
func (e *Endpoint) policyMapPath() string {
	return bpf.LocalMapPath(policymap.MapName, e.ID)
}

// callsMapPath returns the path to cilium tail calls map of an endpoint.
func (e *Endpoint) callsMapPath() string {
	return e.owner.Datapath().Loader().CallsMapPath(e.ID)
}

// callsCustomMapPath returns the path to cilium custom tail calls map of an
// endpoint.
func (e *Endpoint) customCallsMapPath() string {
	return e.owner.Datapath().Loader().CustomCallsMapPath(e.ID)
}

// BPFIpvlanMapPath returns the path to the ipvlan tail call map of an endpoint.
func (e *Endpoint) BPFIpvlanMapPath() string {
	return bpf.LocalMapPath(IpvlanMapName, e.ID)
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

	epStr64, err := e.base64()
	if err == nil {
		var verBase64 string
		verBase64, err = version.Base64()
		if err == nil {
			fmt.Fprintf(fw, " * %s%s:%s\n * \n", ciliumCHeaderPrefix,
				verBase64, epStr64)
		}
	}
	if err != nil {
		e.logStatusLocked(BPF, Warning, fmt.Sprintf("Unable to create a base64: %s", err))
	}

	if e.containerID == "" {
		fmt.Fprintf(fw, " * Docker Network ID: %s\n", e.dockerNetworkID)
		fmt.Fprintf(fw, " * Docker Endpoint ID: %s\n", e.dockerEndpointID)
	} else {
		fmt.Fprintf(fw, " * Container ID: %s\n", e.containerID)
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
				fmt.Fprintf(fw, " * - %s\n", v)
			}
		}
	}
	fw.WriteString(" */\n\n")

	return fw.Flush()
}

// writeHeaderfile writes the lxc_config.h header file of an endpoint
//
// e.mutex must be RLock()ed.
func (e *Endpoint) writeHeaderfile(prefix string) error {
	headerPath := filepath.Join(prefix, common.CHeaderFileName)
	e.getLogger().WithFields(logrus.Fields{
		logfields.Path: headerPath,
	}).Debug("writing header file")

	// Write new contents to a temporary file which will be atomically renamed to the
	// real file at the end of this function. This will make sure we never end up with
	// corrupted header files on the filesystem.
	f, err := renameio.TempFile(prefix, headerPath)
	if err != nil {
		return fmt.Errorf("failed to open temporary file: %s", err)
	}
	defer f.Cleanup()

	// Update DNSRules if any. This is needed because DNSRules also encode allowed destination IPs
	// and those can change anytime we have identity updates in the cluster. If there are no
	// DNSRules (== nil) we don't need to update here, as in that case there are no allowed
	// destinations either.
	if e.DNSRules != nil {
		e.OnDNSPolicyUpdateLocked(e.owner.GetDNSRules(e.ID))
		e.getLogger().WithFields(logrus.Fields{
			logfields.Path: headerPath,
			"DNSRules":     e.DNSRules,
		}).Debug("writing header file with DNSRules")
	}

	if err = e.writeInformationalComments(f); err != nil {
		return err
	}

	if err = e.owner.Datapath().WriteEndpointConfig(f, e); err != nil {
		return err
	}

	err = f.CloseAtomicallyReplace()

	// Create symlink with old header filename, to allow downgrade to pre-1.8
	// Cilium. Can be removed once v1.8 is the oldest supported release.
	// We don't add the symlink for the host endpoint so that it is not
	// restored when downgrading to <1.8. To avoid linking to a
	// nonexistent file, only create the symlink if the header file
	// creation/replacement file succeeded above.
	if !e.IsHost() && err == nil {
		oldHeaderPath := filepath.Join(prefix, oldCHeaderFileName)
		if _, err := os.Stat(oldHeaderPath); err != nil {
			// The symlink doesn't already exists.
			if err := renameio.Symlink(common.CHeaderFileName, oldHeaderPath); err != nil {
				e.getLogger().WithError(err).Error("Failed to create C header file symlink")
			}
		}
	}

	return err
}

// addNewRedirectsFromDesiredPolicy must be called while holding the endpoint lock for
// writing. On success, returns nil; otherwise, returns an error indicating the
// problem that occurred while adding an l7 redirect for the specified policy.
// Must be called with endpoint.mutex Lock()ed.
func (e *Endpoint) addNewRedirectsFromDesiredPolicy(ingress bool, desiredRedirects map[string]bool, proxyWaitGroup *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc) {
	if option.Config.DryMode || e.isProxyDisabled() {
		return nil, nil, nil
	}

	var (
		m            policy.L4PolicyMap
		finalizeList revert.FinalizeList
		revertStack  revert.RevertStack
		updatedStats []*models.ProxyStatistics
	)

	if ingress {
		m = e.desiredPolicy.L4Policy.Ingress
	} else {
		m = e.desiredPolicy.L4Policy.Egress
	}
	mapState := e.desiredPolicy.PolicyMapState

	insertedDesiredMapState := make(map[policy.Key]struct{})
	updatedDesiredMapState := make(policy.MapState)

	for _, l4 := range m {
		// Deny policies do not support redirects
		if l4.IsRedirect() {

			// Check if we are allowing this specific L4 first
			if !mapState.AllowsL4(e, l4) {
				continue
			}

			var redirectPort uint16
			// Only create a redirect if the proxy is NOT running in a sidecar
			// container. If running in a sidecar container, just allow traffic
			// to the port at L4 by setting the proxy port to 0.
			if !e.hasSidecarProxy || l4.L7Parser != policy.ParserTypeHTTP {
				var finalizeFunc revert.FinalizeFunc
				var revertFunc revert.RevertFunc

				proxyID := e.proxyID(l4)
				if proxyID == "" {
					// Skip redirects for which a proxyID cannot be created.
					// This may happen due to the named port mapping not
					// existing or multiple PODs defining the same port name
					// with different port values. The redirect will be created
					// when the mapping is available or when the port name
					// conflicts have been resolved in POD specs.
					continue
				}

				var err error
				redirectPort, err, finalizeFunc, revertFunc = e.proxy.CreateOrUpdateRedirect(l4, proxyID, e, proxyWaitGroup)
				if err != nil {
					revertStack.Revert() // Ignore errors while reverting. This is best-effort.
					return err, nil, nil
				}
				finalizeList.Append(finalizeFunc)
				revertStack.Push(revertFunc)

				if e.realizedRedirects == nil {
					e.realizedRedirects = make(map[string]uint16)
				}
				if _, found := e.realizedRedirects[proxyID]; !found {
					revertStack.Push(func() error {
						delete(e.realizedRedirects, proxyID)
						return nil
					})
				}
				e.realizedRedirects[proxyID] = redirectPort

				desiredRedirects[proxyID] = true

				// Update the endpoint API model to report that Cilium manages a
				// redirect for that port.
				e.proxyStatisticsMutex.Lock()
				proxyStats := e.getProxyStatisticsLocked(proxyID, string(l4.L7Parser), uint16(l4.Port), l4.Ingress)
				proxyStats.AllocatedProxyPort = int64(redirectPort)
				e.proxyStatisticsMutex.Unlock()

				updatedStats = append(updatedStats, proxyStats)
			}

			if e.desiredPolicy == e.realizedPolicy {
				// Any map updates when a new policy has not been calculated are taken care by incremental map updates.
				continue
			}

			// Set the proxy port in the policy map.
			var direction trafficdirection.TrafficDirection
			if l4.Ingress {
				direction = trafficdirection.Ingress
			} else {
				direction = trafficdirection.Egress
			}

			keysFromFilter := l4.ToMapState(e, direction)

			for keyFromFilter, entry := range keysFromFilter {
				if oldEntry, ok := e.desiredPolicy.PolicyMapState[keyFromFilter]; ok {
					// Keep the original old entry for revert if there are duplicate keys,
					// which are possible due to named ports resolving to the same number.
					if _, isDup := updatedDesiredMapState[keyFromFilter]; !isDup {
						updatedDesiredMapState[keyFromFilter] = oldEntry
					}
				} else {
					insertedDesiredMapState[keyFromFilter] = struct{}{}
				}
				if entry.IsRedirectEntry() {
					entry.ProxyPort = redirectPort
				}
				e.desiredPolicy.PolicyMapState[keyFromFilter] = entry
			}
		}
	}

	revertStack.Push(func() error {
		// Restore the proxy stats.
		e.proxyStatisticsMutex.Lock()
		for _, stats := range updatedStats {
			stats.AllocatedProxyPort = 0
		}
		e.proxyStatisticsMutex.Unlock()

		// Restore the desired policy map state.
		for key := range insertedDesiredMapState {
			delete(e.desiredPolicy.PolicyMapState, key)
		}
		for key, entry := range updatedDesiredMapState {
			e.desiredPolicy.PolicyMapState[key] = entry
		}
		return nil
	})

	return nil, finalizeList.Finalize, revertStack.Revert
}

func (e *Endpoint) addVisibilityRedirects(ingress bool, desiredRedirects map[string]bool, proxyWaitGroup *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc) {
	var (
		visPolicy               policy.DirectionalVisibilityPolicy
		direction               trafficdirection.TrafficDirection
		policyEnabled           bool
		finalizeList            revert.FinalizeList
		revertStack             revert.RevertStack
		insertedDesiredMapState = make(map[policy.Key]struct{})
	)

	if e.visibilityPolicy == nil {
		return nil, finalizeList.Finalize, revertStack.Revert
	}

	if ingress {
		visPolicy = e.visibilityPolicy.Ingress
		direction = trafficdirection.Ingress
		policyEnabled = e.desiredPolicy.IngressPolicyEnabled
	} else {
		visPolicy = e.visibilityPolicy.Egress
		direction = trafficdirection.Egress
		policyEnabled = e.desiredPolicy.EgressPolicyEnabled
	}

	// If policy is enabled, do not generate visibility redirects for now.
	// TODO: generate visibility redirects as well if policy is enabled and
	// the L4Policy would allow the traffic at L3/L4 for an entry in the
	// VisibilityPolicy.
	if policyEnabled {
		return nil, finalizeList.Finalize, revertStack.Revert
	}

	updatedStats := make([]*models.ProxyStatistics, 0, len(visPolicy))
	for _, visMeta := range visPolicy {
		// Create a redirect for every entry in the visibility policy.
		if e.hasSidecarProxy && visMeta.Parser == policy.ParserTypeHTTP {
			continue
		}
		var (
			redirectPort uint16
			err          error
			finalizeFunc revert.FinalizeFunc
			revertFunc   revert.RevertFunc
		)
		proxyID := policy.ProxyID(e.ID, visMeta.Ingress, visMeta.Proto.String(), visMeta.Port)
		redirectPort, err, finalizeFunc, revertFunc = e.proxy.CreateOrUpdateRedirect(visMeta, proxyID, e, proxyWaitGroup)
		if err != nil {
			revertStack.Revert() // Ignore errors while reverting. This is best-effort.
			return err, nil, nil
		}
		finalizeList.Append(finalizeFunc)
		revertStack.Push(revertFunc)

		if e.realizedRedirects == nil {
			e.realizedRedirects = make(map[string]uint16)
		}
		if _, found := e.realizedRedirects[proxyID]; !found {
			revertStack.Push(func() error {
				delete(e.realizedRedirects, proxyID)
				return nil
			})
		}
		e.realizedRedirects[proxyID] = redirectPort

		desiredRedirects[proxyID] = true

		// Update the endpoint API model to report that Cilium manages a
		// redirect for that port.
		e.proxyStatisticsMutex.Lock()
		proxyStats := e.getProxyStatisticsLocked(proxyID, string(visMeta.Parser), visMeta.Port, visMeta.Ingress)
		proxyStats.AllocatedProxyPort = int64(redirectPort)
		e.proxyStatisticsMutex.Unlock()

		updatedStats = append(updatedStats, proxyStats)

		newKey := policy.Key{
			DestPort:         visMeta.Port,
			Nexthdr:          uint8(visMeta.Proto),
			TrafficDirection: direction.Uint8(),
		}

		derivedFrom := labels.LabelArrayList{
			labels.LabelArray{
				labels.NewLabel(policy.LabelKeyPolicyDerivedFrom, policy.LabelVisibilityAnnotation, labels.LabelSourceReserved),
			},
		}
		entry := policy.NewMapStateEntry(nil, derivedFrom, true, false)
		entry.ProxyPort = redirectPort

		e.desiredPolicy.PolicyMapState[newKey] = entry
		insertedDesiredMapState[newKey] = struct{}{}
	}

	revertStack.Push(func() error {
		// Restore the proxy stats.
		e.proxyStatisticsMutex.Lock()
		for _, stats := range updatedStats {
			stats.AllocatedProxyPort = 0
		}
		e.proxyStatisticsMutex.Unlock()

		// Restore the desired policy map state.
		for key := range insertedDesiredMapState {
			delete(e.desiredPolicy.PolicyMapState, key)
		}
		return nil
	})

	return nil, finalizeList.Finalize, revertStack.Revert
}

// addNewRedirects must be called while holding the endpoint lock for writing.
// On success, returns nil; otherwise, returns an error indicating the problem
// that occurred while adding an l7 redirect for the specified policy.
// The returned map contains the exact set of IDs of proxy redirects that is
// required to implement the given L4 policy.
// Must be called with endpoint.mutex Lock()ed.
func (e *Endpoint) addNewRedirects(proxyWaitGroup *completion.WaitGroup) (desiredRedirects map[string]bool, err error, finalizeFunc revert.FinalizeFunc, revertFunc revert.RevertFunc) {
	var (
		finalizeList revert.FinalizeList
		revertStack  revert.RevertStack
		ff           revert.FinalizeFunc
		rf           revert.RevertFunc
	)

	defer func() {
		// In case updates partially succeeded, and subsequently failed,
		// revert.
		if err != nil {
			revertStack.Revert()
		}
	}()

	desiredRedirects = make(map[string]bool)

	for dirLogStr, ingress := range map[string]bool{"ingress": true, "egress": false} {
		err, ff, rf = e.addNewRedirectsFromDesiredPolicy(ingress, desiredRedirects, proxyWaitGroup)
		if err != nil {
			return desiredRedirects, fmt.Errorf("unable to allocate %s redirects: %s", dirLogStr, err), nil, nil
		}
		finalizeList.Append(ff)
		revertStack.Push(rf)

		err, ff, rf = e.addVisibilityRedirects(ingress, desiredRedirects, proxyWaitGroup)
		if err != nil {
			return desiredRedirects, fmt.Errorf("unable to allocate %s visibility redirects: %s", dirLogStr, err), nil, nil
		}
		finalizeList.Append(ff)
		revertStack.Push(rf)
	}

	return desiredRedirects, nil, finalizeList.Finalize, func() error {
		e.getLogger().Debug("Reverting proxy redirect additions")

		err := revertStack.Revert()

		e.getLogger().Debug("Finished reverting proxy redirect additions")

		return err
	}
}

// Must be called with endpoint.mutex Lock()ed.
func (e *Endpoint) removeOldRedirects(desiredRedirects map[string]bool, proxyWaitGroup *completion.WaitGroup) (revert.FinalizeFunc, revert.RevertFunc) {
	if option.Config.DryMode {
		return nil, nil
	}

	var finalizeList revert.FinalizeList
	var revertStack revert.RevertStack
	removedRedirects := make(map[string]uint16, len(e.realizedRedirects))
	updatedStats := make(map[uint16]*models.ProxyStatistics, len(e.realizedRedirects))

	for id, redirectPort := range e.realizedRedirects {
		// Remove only the redirects that are not required.
		if desiredRedirects[id] {
			continue
		}

		err, finalizeFunc, revertFunc := e.proxy.RemoveRedirect(id, proxyWaitGroup)
		if err != nil {
			e.getLogger().WithError(err).WithField(logfields.L4PolicyID, id).Warn("Error while removing proxy redirect")
			continue
		}
		finalizeList.Append(finalizeFunc)
		revertStack.Push(revertFunc)

		delete(e.realizedRedirects, id)
		removedRedirects[id] = redirectPort

		// Update the endpoint API model to report that no redirect is
		// active or known for that port anymore. We never delete stats
		// until an endpoint is deleted, so we only set the redirect port
		// to 0.
		e.proxyStatisticsMutex.Lock()
		if proxyStats, ok := e.proxyStatistics[id]; ok {
			updatedStats[redirectPort] = proxyStats
			proxyStats.AllocatedProxyPort = 0
		} else {
			e.getLogger().WithField(logfields.L4PolicyID, id).Warn("Proxy stats not found")
		}
		e.proxyStatisticsMutex.Unlock()
	}

	return finalizeList.Finalize,
		func() error {
			e.getLogger().Debug("Reverting proxy redirect removals")

			// Restore the proxy stats.
			e.proxyStatisticsMutex.Lock()
			for redirectPort, stats := range updatedStats {
				stats.AllocatedProxyPort = int64(redirectPort)
			}
			e.proxyStatisticsMutex.Unlock()

			for id, redirectPort := range removedRedirects {
				e.realizedRedirects[id] = redirectPort
			}

			err := revertStack.Revert()

			e.getLogger().Debug("Finished reverting proxy redirect removals")

			return err
		}
}

// regenerateBPF rewrites all headers and updates all BPF maps to reflect the
// specified endpoint.
// ReloadDatapath forces the datapath programs to be reloaded. It does
// not guarantee recompilation of the programs.
// Must be called with endpoint.mutex not held and endpoint.buildMutex held.
//
// Returns the policy revision number when the regeneration has called,
// Whether the new state dir is populated with all new BPF state files, and
// and an error if something failed.
func (e *Endpoint) regenerateBPF(regenContext *regenerationContext) (revnum uint64, stateDirComplete bool, reterr error) {
	var (
		err                 error
		compilationExecuted bool
		headerfileChanged   bool
	)

	stats := &regenContext.Stats
	stats.waitingForLock.Start()

	datapathRegenCtxt := regenContext.datapathRegenerationContext

	// Make sure that owner is not compiling base programs while we are
	// regenerating an endpoint.
	e.owner.GetCompilationLock().RLock()
	stats.waitingForLock.End(true)
	defer e.owner.GetCompilationLock().RUnlock()

	datapathRegenCtxt.prepareForProxyUpdates(regenContext.parentContext)
	defer datapathRegenCtxt.completionCancel()

	headerfileChanged, err = e.runPreCompilationSteps(regenContext)

	// Keep track of the side-effects of the regeneration that need to be
	// reverted in case of failure.
	// Also keep track of the regeneration finalization code that can't be
	// reverted, and execute it in case of regeneration success.
	defer func() {
		// Ignore finalizing of proxy state in dry mode.
		if !option.Config.DryMode {
			e.finalizeProxyState(regenContext, reterr)
		}
	}()

	if err != nil {
		return 0, compilationExecuted, err
	}

	// No need to compile BPF in dry mode.
	if option.Config.DryMode {
		return e.nextPolicyRevision, false, nil
	}

	// Wait for connection tracking cleaning to complete
	stats.waitingForCTClean.Start()
	<-datapathRegenCtxt.ctCleaned
	stats.waitingForCTClean.End(true)

	stats.prepareBuild.End(true)

	compilationExecuted, err = e.realizeBPFState(regenContext)
	if err != nil {
		return datapathRegenCtxt.epInfoCache.revision, compilationExecuted, err
	}

	if !datapathRegenCtxt.epInfoCache.IsHost() {
		// Hook the endpoint into the endpoint and endpoint to policy tables then expose it
		stats.mapSync.Start()
		epErr := eppolicymap.WriteEndpoint(datapathRegenCtxt.epInfoCache, e.policyMap)
		err = lxcmap.WriteEndpoint(datapathRegenCtxt.epInfoCache)
		stats.mapSync.End(err == nil)
		if epErr != nil {
			e.logStatusLocked(BPF, Warning, fmt.Sprintf("Unable to sync EpToPolicy Map continue with Sockmap support: %s", epErr))
		}
		if err != nil {
			return 0, compilationExecuted, fmt.Errorf("Exposing new BPF failed: %s", err)
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
		return 0, compilationExecuted, fmt.Errorf("Error while configuring proxy redirects: %s", err)
	}

	stats.waitingForLock.Start()
	err = e.lockAlive()
	stats.waitingForLock.End(err == nil)
	if err != nil {
		return 0, compilationExecuted, err
	}
	defer e.unlock()

	e.ctCleaned = true

	// Synchronously try to update PolicyMap for this endpoint. If any
	// part of updating the PolicyMap fails, bail out.
	// Unfortunately, this means that the map will be in an inconsistent
	// state with the current program (if it exists) for this endpoint.
	// GH-3897 would fix this by creating a new map to do an atomic swap
	// with the old one.
	//
	// This must be done after allocating the new redirects, to update the
	// policy map with the new proxy ports.
	stats.mapSync.Start()
	err = e.syncPolicyMap()
	stats.mapSync.End(err == nil)
	if err != nil {
		return 0, compilationExecuted, fmt.Errorf("unable to regenerate policy because PolicyMap synchronization failed: %s", err)
	}

	stateDirComplete = headerfileChanged && compilationExecuted
	return datapathRegenCtxt.epInfoCache.revision, stateDirComplete, err
}

func (e *Endpoint) realizeBPFState(regenContext *regenerationContext) (compilationExecuted bool, err error) {
	stats := &regenContext.Stats
	datapathRegenCtxt := regenContext.datapathRegenerationContext

	e.getLogger().WithField(fieldRegenLevel, datapathRegenCtxt.regenerationLevel).Debug("Preparing to compile BPF")

	if datapathRegenCtxt.regenerationLevel > regeneration.RegenerateWithoutDatapath {
		if e.Options.IsEnabled(option.Debug) {
			debugFunc := log.WithFields(logrus.Fields{logfields.EndpointID: e.StringID()}).Debugf
			ctx, cancel := context.WithCancel(regenContext.parentContext)
			defer cancel()
			loadinfo.LogPeriodicSystemLoad(ctx, debugFunc, time.Second)
		}

		// Compile and install BPF programs for this endpoint
		if datapathRegenCtxt.regenerationLevel == regeneration.RegenerateWithDatapathRebuild {
			err = e.owner.Datapath().Loader().CompileAndLoad(datapathRegenCtxt.completionCtx, datapathRegenCtxt.epInfoCache, &stats.datapathRealization)
			e.getLogger().WithError(err).Info("Regenerated endpoint BPF program")
			compilationExecuted = true
		} else if datapathRegenCtxt.regenerationLevel == regeneration.RegenerateWithDatapathRewrite {
			err = e.owner.Datapath().Loader().CompileOrLoad(datapathRegenCtxt.completionCtx, datapathRegenCtxt.epInfoCache, &stats.datapathRealization)
			if err == nil {
				e.getLogger().Info("Rewrote endpoint BPF program")
			} else {
				e.getLogger().WithError(err).Error("Error while rewriting endpoint BPF program")
			}
			compilationExecuted = true
		} else { // RegenerateWithDatapathLoad
			err = e.owner.Datapath().Loader().ReloadDatapath(datapathRegenCtxt.completionCtx, datapathRegenCtxt.epInfoCache, &stats.datapathRealization)
			if err == nil {
				e.getLogger().Info("Reloaded endpoint BPF program")
			} else {
				e.getLogger().WithError(err).Error("Error while reloading endpoint BPF program")
			}
		}

		if err != nil {
			return compilationExecuted, err
		}
		e.bpfHeaderfileHash = datapathRegenCtxt.bpfHeaderfilesHash
	} else {
		e.getLogger().WithField(logfields.BPFHeaderfileHash, datapathRegenCtxt.bpfHeaderfilesHash).
			Debug("BPF header file unchanged, skipping BPF compilation and installation")
	}

	return compilationExecuted, nil
}

// runPreCompilationSteps runs all of the regeneration steps that are necessary
// right before compiling the BPF for the given endpoint.
// The endpoint mutex must not be held.
//
// Returns whether the headerfile changed and/or an error.
func (e *Endpoint) runPreCompilationSteps(regenContext *regenerationContext) (headerfileChanged bool, preCompilationError error) {
	stats := &regenContext.Stats
	datapathRegenCtxt := regenContext.datapathRegenerationContext

	stats.waitingForLock.Start()
	err := e.lockAlive()
	stats.waitingForLock.End(err == nil)
	if err != nil {
		return false, err
	}

	defer e.unlock()

	currentDir := datapathRegenCtxt.currentDir
	nextDir := datapathRegenCtxt.nextDir

	// In the first ever regeneration of the endpoint, the conntrack table
	// is cleaned from the new endpoint IPs as it is guaranteed that any
	// pre-existing connections using that IP are now invalid.
	if !e.ctCleaned {
		go func() {
			if !option.Config.DryMode {
				ipv4 := option.Config.EnableIPv4
				ipv6 := option.Config.EnableIPv6
				exists := ctmap.Exists(nil, ipv4, ipv6)
				if e.ConntrackLocal() {
					exists = ctmap.Exists(e, ipv4, ipv6)
				}
				if exists {
					e.scrubIPsInConntrackTable()
				}
			}
			close(datapathRegenCtxt.ctCleaned)
		}()
	} else {
		close(datapathRegenCtxt.ctCleaned)
	}

	// If dry mode is enabled, no further changes to BPF maps are performed
	if option.Config.DryMode {

		// Compute policy for this endpoint.
		if err = e.regeneratePolicy(); err != nil {
			return false, fmt.Errorf("Unable to regenerate policy: %s", err)
		}

		_ = e.updateAndOverrideEndpointOptions(nil)

		// Dry mode needs Network Policy Updates, but the proxy wait group must
		// not be initialized, as there is no proxy ACKing the changes.
		if err, _ = e.updateNetworkPolicy(nil); err != nil {
			return false, err
		}

		if err = e.writeHeaderfile(nextDir); err != nil {
			return false, fmt.Errorf("Unable to write header file: %s", err)
		}

		log.WithField(logfields.EndpointID, e.ID).Debug("Skipping bpf updates due to dry mode")
		return false, nil
	}

	if e.policyMap == nil {
		e.policyMap, _, err = policymap.OpenOrCreate(e.policyMapPath())
		if err != nil {
			return false, err
		}
		// Clean up map contents
		e.getLogger().Debug("flushing old PolicyMap")
		e.policyDebug(nil, "runPreCompilationSteps flushing old PolicyMap")
		err = e.policyMap.DeleteAll()
		if err != nil {
			return false, err
		}

		// Also reset the in-memory state of the realized state as the
		// BPF map content is guaranteed to be empty right now.
		e.realizedPolicy.PolicyMapState = make(policy.MapState)
		e.initPolicyMapPressureMetric()
		e.updatePolicyMapPressureMetric()
	}

	// Only generate & populate policy map if a security identity is set up for
	// this endpoint.
	if e.SecurityIdentity != nil {
		stats.policyCalculation.Start()
		err = e.regeneratePolicy()
		stats.policyCalculation.End(err == nil)
		if err != nil {
			return false, fmt.Errorf("unable to regenerate policy for '%s': %s", e.StringID(), err)
		}

		_ = e.updateAndOverrideEndpointOptions(nil)

		// Walk the L4Policy to add new redirects and update the desired policy for existing redirects.
		// Do this before updating the bpf policy maps, so that the proxies are ready when new traffic
		// is redirected to them.
		var (
			desiredRedirects map[string]bool
			finalizeFunc     revert.FinalizeFunc
			revertFunc       revert.RevertFunc
		)
		if e.desiredPolicy != nil {
			stats.proxyConfiguration.Start()
			// Deny policies do not support redirects
			desiredRedirects, err, finalizeFunc, revertFunc = e.addNewRedirects(datapathRegenCtxt.proxyWaitGroup)
			stats.proxyConfiguration.End(err == nil)
			if err != nil {
				return false, err
			}
			datapathRegenCtxt.finalizeList.Append(finalizeFunc)
			datapathRegenCtxt.revertStack.Push(revertFunc)
		}

		// Configure the new network policy with the proxies.
		//
		// This must be done after adding new redirects above, as waiting for policy update ACKs is
		// disabled when there are no listeners, which is the case before the first redirect is added.
		//
		// Do this before updating the bpf policy maps below, so that the proxy listeners have a chance to be
		// ready when new traffic is redirected to them.
		stats.proxyPolicyCalculation.Start()
		err, networkPolicyRevertFunc := e.updateNetworkPolicy(datapathRegenCtxt.proxyWaitGroup)
		stats.proxyPolicyCalculation.End(err == nil)
		if err != nil {
			return false, err
		}
		datapathRegenCtxt.revertStack.Push(networkPolicyRevertFunc)

		// Synchronously try to update PolicyMap for this endpoint. If any
		// part of updating the PolicyMap fails, bail out and do not generate
		// BPF. Unfortunately, this means that the map will be in an inconsistent
		// state with the current program (if it exists) for this endpoint.
		// GH-3897 would fix this by creating a new map to do an atomic swap
		// with the old one.
		stats.mapSync.Start()
		err = e.syncPolicyMap()
		stats.mapSync.End(err == nil)
		if err != nil {
			return false, fmt.Errorf("unable to regenerate policy because PolicyMap synchronization failed: %s", err)
		}

		// At this point, traffic is no longer redirected to the proxy for
		// now-obsolete redirects, since we synced the updated policy map above.
		// It's now safe to remove the redirects from the proxy's configuration.
		stats.proxyConfiguration.Start()
		finalizeFunc, revertFunc = e.removeOldRedirects(desiredRedirects, datapathRegenCtxt.proxyWaitGroup)
		datapathRegenCtxt.finalizeList.Append(finalizeFunc)
		datapathRegenCtxt.revertStack.Push(revertFunc)
		stats.proxyConfiguration.End(true)
	}

	stats.prepareBuild.Start()
	defer func() {
		stats.prepareBuild.End(preCompilationError == nil)
	}()

	// Avoid BPF program compilation and installation if the headerfile for the endpoint
	// or the node have not changed.
	datapathRegenCtxt.bpfHeaderfilesHash, err = e.owner.Datapath().Loader().EndpointHash(e)
	if err != nil {
		e.getLogger().WithError(err).Warn("Unable to hash header file")
		datapathRegenCtxt.bpfHeaderfilesHash = ""
		headerfileChanged = true
	} else {
		headerfileChanged = (datapathRegenCtxt.bpfHeaderfilesHash != e.bpfHeaderfileHash)
		e.getLogger().WithField(logfields.BPFHeaderfileHash, datapathRegenCtxt.bpfHeaderfilesHash).
			Debugf("BPF header file hashed (was: %q)", e.bpfHeaderfileHash)
	}

	if headerfileChanged {
		datapathRegenCtxt.regenerationLevel = regeneration.RegenerateWithDatapathRewrite
	}
	if datapathRegenCtxt.regenerationLevel >= regeneration.RegenerateWithDatapathRewrite {
		if err := e.writeHeaderfile(nextDir); err != nil {
			return false, fmt.Errorf("unable to write header file: %s", err)
		}
	}

	// Cache endpoint information so that we can release the endpoint lock.
	if datapathRegenCtxt.regenerationLevel >= regeneration.RegenerateWithDatapathRewrite {
		datapathRegenCtxt.epInfoCache = e.createEpInfoCache(nextDir)
	} else {
		datapathRegenCtxt.epInfoCache = e.createEpInfoCache(currentDir)
	}
	if datapathRegenCtxt.epInfoCache == nil {
		return headerfileChanged, fmt.Errorf("Unable to cache endpoint information")
	}

	return headerfileChanged, nil
}

func (e *Endpoint) finalizeProxyState(regenContext *regenerationContext, err error) {
	datapathRegenCtx := regenContext.datapathRegenerationContext
	if err == nil {
		// Always execute the finalization code, even if the endpoint is
		// terminating, in order to properly release resources.
		e.unconditionalLock()
		e.getLogger().Debug("Finalizing successful endpoint regeneration")
		datapathRegenCtx.finalizeList.Finalize()
		e.unlock()
	} else {
		if err := e.lockAlive(); err != nil {
			e.getLogger().WithError(err).Debug("Skipping unnecessary reverting of endpoint regeneration changes")
			return
		}
		e.getLogger().Debug("Reverting endpoint changes after BPF regeneration failed")
		if err := datapathRegenCtx.revertStack.Revert(); err != nil {
			e.getLogger().WithError(err).Error("Reverting endpoint regeneration changes failed")
		}
		e.getLogger().Debug("Finished reverting endpoint changes after BPF regeneration failed")
		e.unlock()
	}
}

// InitMap creates the policy map in the kernel.
func (e *Endpoint) InitMap() error {
	_, err := policymap.Create(e.policyMapPath())
	return err
}

// deleteMaps releases references to all BPF maps associated with this
// endpoint.
//
// For each error that occurs while releasing these references, an error is
// added to the resulting error slice which is returned.
//
// Returns nil on success.
func (e *Endpoint) deleteMaps() []error {
	var errors []error

	maps := map[string]string{
		"policy": e.policyMapPath(),
		"calls":  e.callsMapPath(),
		"egress": e.BPFIpvlanMapPath(),
	}
	if !e.isHost {
		maps["custom"] = e.customCallsMapPath()
	}
	for name, path := range maps {
		if err := os.RemoveAll(path); err != nil {
			errors = append(errors, fmt.Errorf("unable to remove %s map file %s: %s", name, path, err))
		}
	}

	if e.ConntrackLocalLocked() {
		// Remove local connection tracking maps
		for _, m := range ctmap.LocalMaps(e, option.Config.EnableIPv4, option.Config.EnableIPv6) {
			ctPath, err := m.Path()
			if err == nil {
				err = os.RemoveAll(ctPath)
			}
			if err != nil {
				errors = append(errors, fmt.Errorf("unable to remove CT map %s: %s", ctPath, err))
			}
		}
	}

	// Remove handle_policy() tail call entry for EP
	if err := policymap.RemoveGlobalMapping(uint32(e.ID)); err != nil {
		errors = append(errors, fmt.Errorf("unable to remove endpoint from global policy map: %s", err))
	}

	// Remove rate-limit from bandwidth manager map.
	if e.bps != 0 && option.Config.EnableBandwidthManager {
		if err := bwmap.Delete(e.ID); err != nil {
			errors = append(errors, fmt.Errorf("unable to remote endpoint from bandwidth manager map: %s", err))
		}
	}

	return errors
}

// DeleteBPFProgramLocked delete the BPF program associated with the endpoint's
// veth interface.
func (e *Endpoint) DeleteBPFProgramLocked() error {
	e.getLogger().Debug("deleting bpf program from endpoint")
	return loader.RemoveTCFilters(e.ifName, netlink.HANDLE_MIN_INGRESS)
}

// garbageCollectConntrack will run the ctmap.GC() on either the endpoint's
// local conntrack table or the global conntrack table.
//
// The endpoint lock must be held
func (e *Endpoint) garbageCollectConntrack(filter *ctmap.GCFilter) {
	var maps []*ctmap.Map

	if e.ConntrackLocalLocked() {
		maps = ctmap.LocalMaps(e, option.Config.EnableIPv4, option.Config.EnableIPv6)
	} else {
		maps = ctmap.GlobalMaps(option.Config.EnableIPv4, option.Config.EnableIPv6)
	}
	for _, m := range maps {
		if err := m.Open(); err != nil {
			// If the CT table doesn't exist, there's nothing to GC.
			scopedLog := log.WithError(err).WithField(logfields.EndpointID, e.ID)
			if os.IsNotExist(err) {
				scopedLog.WithError(err).Debug("Skipping GC for endpoint")
			} else {
				scopedLog.WithError(err).Warn("Unable to open map")
			}
			continue
		}
		defer m.Close()

		ctmap.GC(m, filter)
	}
}

func (e *Endpoint) scrubIPsInConntrackTableLocked() {
	e.garbageCollectConntrack(&ctmap.GCFilter{
		MatchIPs: map[string]struct{}{
			e.IPv4.String(): {},
			e.IPv6.String(): {},
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
// claned.
//
// The endpoint lock must NOT be held.
func (e *Endpoint) SkipStateClean() {
	// Mark conntrack as already cleaned
	e.unconditionalLock()
	e.ctCleaned = true
	e.unlock()
}

func (e *Endpoint) initPolicyMapPressureMetric() {
	if !option.Config.MetricsConfig.BPFMapPressure {
		return
	}

	if e.policyMapPressureGauge != nil {
		return
	}

	e.policyMapPressureGauge = metrics.NewBPFMapPressureGauge(e.policyMap.NonPrefixedName(), policymap.PressureMetricThreshold)
}

func (e *Endpoint) updatePolicyMapPressureMetric() {
	if e.policyMapPressureGauge == nil {
		return
	}

	value := float64(len(e.realizedPolicy.PolicyMapState)) / float64(e.policyMap.MapInfo.MaxEntries)
	e.policyMapPressureGauge.Set(value)
}

// The bool pointed by hadProxy, if not nil, will be set to 'true' if
// the deleted entry had a proxy port assigned to it.  *hadProxy is
// not otherwise changed (e.g., it is never set to 'false').
func (e *Endpoint) deletePolicyKey(keyToDelete policy.Key, incremental bool, hadProxy *bool) bool {
	// Convert from policy.Key to policymap.Key
	policymapKey := policymap.PolicyKey{
		Identity:         keyToDelete.Identity,
		DestPort:         keyToDelete.DestPort,
		Nexthdr:          keyToDelete.Nexthdr,
		TrafficDirection: keyToDelete.TrafficDirection,
	}

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
		e.getLogger().WithError(err).WithField(logfields.BPFMapKey, policymapKey).Error("Failed to delete PolicyMap key")
		return false
	}

	var entry policy.MapStateEntry
	var ok bool
	if entry, ok = e.realizedPolicy.PolicyMapState[keyToDelete]; ok && entry.ProxyPort != 0 && hadProxy != nil {
		*hadProxy = true
	}

	// Operation was successful, remove from realized state.
	delete(e.realizedPolicy.PolicyMapState, keyToDelete)
	e.updatePolicyMapPressureMetric()

	e.policyDebug(logrus.Fields{
		logfields.BPFMapKey:   keyToDelete,
		logfields.BPFMapValue: entry,
		"incremental":         incremental,
	}, "deletePolicyKey")

	return true
}

func (e *Endpoint) addPolicyKey(keyToAdd policy.Key, entry policy.MapStateEntry, incremental bool) bool {
	// Convert from policy.Key to policymap.Key
	policymapKey := policymap.PolicyKey{
		Identity:         keyToAdd.Identity,
		DestPort:         keyToAdd.DestPort,
		Nexthdr:          keyToAdd.Nexthdr,
		TrafficDirection: keyToAdd.TrafficDirection,
	}

	var err error
	if entry.IsDeny {
		err = e.policyMap.DenyKey(policymapKey)
	} else {
		err = e.policyMap.AllowKey(policymapKey, entry.ProxyPort)
	}
	if err != nil {
		e.getLogger().WithError(err).WithFields(logrus.Fields{
			logfields.BPFMapKey: policymapKey,
			logfields.Port:      entry.ProxyPort,
		}).Error("Failed to add PolicyMap key")
		return false
	}

	// Operation was successful, add to realized state.
	e.realizedPolicy.PolicyMapState[keyToAdd] = entry
	e.updatePolicyMapPressureMetric()

	e.policyDebug(logrus.Fields{
		logfields.BPFMapKey:   keyToAdd,
		logfields.BPFMapValue: entry,
		"incremental":         incremental,
	}, "addPolicyKey")
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

	e.policyDebug(nil, "ApplyPolicyMapChanges")

	proxyChanges, err := e.applyPolicyMapChanges()
	if err != nil {
		return err
	}

	if proxyChanges {
		// Ignoring the revertFunc; keep all successful changes even if some fail.
		err, _ = e.updateNetworkPolicy(proxyWaitGroup)
	} else {
		// Allow caller to wait for the current network policy to be acked
		e.useCurrentNetworkPolicy(proxyWaitGroup)
	}

	return err
}

// applyPolicyMapChanges applies any incremental policy map changes
// collected on the desired policy.
func (e *Endpoint) applyPolicyMapChanges() (proxyChanges bool, err error) {
	errors := 0

	e.policyDebug(nil, "applyPolicyMapChanges")

	//  Note that after successful endpoint regeneration the
	//  desired and realized policies are the same pointer. During
	//  the bpf regeneration possible incremental updates are
	//  collected on the newly computed desired policy, which is
	//  not fully realized yet. This is why we get the map changes
	//  from the desired policy here.
	//  ConsumeMapChanges() applies the incremental updates to the
	//  desired policy and only returns changes that need to be
	//  applied to the Endpoint's bpf policy map.
	adds, deletes := e.desiredPolicy.ConsumeMapChanges()

	// Add policy map entries before deleting to avoid transient drops
	for keyToAdd, entry := range adds {
		// Redirect entries currently come in with a dummy redirect port ("1"), replace it with
		// the actual proxy port number. This is due to the fact that proxies may not yet have
		// bound to a specific port when a proxy policy is first instantiated.
		if entry.IsRedirectEntry() {
			entry.ProxyPort = e.realizedRedirects[policy.ProxyIDFromKey(e.ID, keyToAdd)]
			if entry.ProxyPort != 0 {
				proxyChanges = true
			}
		}
		if !e.addPolicyKey(keyToAdd, entry, true) {
			errors++
		}
	}

	for keyToDelete := range deletes {
		if !e.deletePolicyKey(keyToDelete, true, &proxyChanges) {
			errors++
		}
	}

	if errors > 0 {
		return proxyChanges, fmt.Errorf("updating desired PolicyMap state failed")
	} else if len(adds)+len(deletes) > 0 {
		e.getLogger().WithFields(logrus.Fields{
			logfields.AddedPolicyID:   adds,
			logfields.DeletedPolicyID: deletes,
		}).Debug("Applied policy map updates due identity changes")
	}

	return proxyChanges, nil
}

// syncPolicyMap updates the bpf policy map state based on the
// difference between the realized and desired policy state without
// dumping the bpf policy map.
func (e *Endpoint) syncPolicyMap() error {
	// Apply pending policy map changes first so that desired map is up-to-date before
	// we diff the maps below.
	_, err := e.applyPolicyMapChanges()
	if err != nil {
		return err
	}

	// Nothing to do if the desired policy is already fully realized.
	if e.realizedPolicy == e.desiredPolicy {
		e.policyDebug(nil, "syncPolicyMap(): not syncing as desired == realized")
		return nil
	}

	// Diffs between the maps are expected here, so do not bother collecting them
	_, _, err = e.syncDesiredPolicyMapWith(e.realizedPolicy.PolicyMapState, false)
	return err
}

// syncDesiredPolicyMapWith updates the bpf policy map state based on the
// difference between the given 'realized' and desired policy state without
// dumping the bpf policy map.
func (e *Endpoint) syncDesiredPolicyMapWith(realized policy.MapState, withDiffs bool) (diffCount int, diffs []policy.MapChange, err error) {
	errors := 0

	// Add policy map entries before deleting to avoid transient drops
	for keyToAdd, entry := range e.desiredPolicy.PolicyMapState {
		if oldEntry, ok := realized[keyToAdd]; !ok || !oldEntry.DatapathEqual(&entry) {
			// Redirect entries currently come in with a dummy redirect port ("1"), replace it with
			// the actual proxy port number. This is due to the fact that proxies may not yet have
			// bound to a specific port when a proxy policy is first instantiated.
			if entry.IsRedirectEntry() {
				// Will change to 0 if on a sidecar
				entry.ProxyPort = e.realizedRedirects[policy.ProxyIDFromKey(e.ID, keyToAdd)]
			}
			if !e.addPolicyKey(keyToAdd, entry, false) {
				errors++
			}
			diffCount++
			if withDiffs {
				diffs = append(diffs, policy.MapChange{Add: true, Key: keyToAdd, Value: entry})
			}
		}
	}

	// Delete policy keys present in the realized state, but not present in the desired state
	for keyToDelete := range realized {
		// If key that is in realized state is not in desired state, just remove it.
		if entry, ok := e.desiredPolicy.PolicyMapState[keyToDelete]; !ok {
			if !e.deletePolicyKey(keyToDelete, false, nil) {
				errors++
			}
			diffCount++
			if withDiffs {
				diffs = append(diffs, policy.MapChange{Add: false, Key: keyToDelete, Value: entry})
			}
		}
	}

	if errors > 0 {
		err = fmt.Errorf("syncPolicyMap failed")
	}
	return diffCount, diffs, err
}

func (e *Endpoint) dumpPolicyMapToMapState() (policy.MapState, error) {
	currentMap := make(policy.MapState)

	cb := func(key bpf.MapKey, value bpf.MapValue) {
		// Convert key to host byte-order. ToHost() makes a copy.
		keyHostOrder := key.(*policymap.PolicyKey).ToHost()
		// Convert from policymap.Key to policy.Key
		policyKey := policy.Key{
			Identity:         keyHostOrder.Identity,
			DestPort:         keyHostOrder.DestPort,
			Nexthdr:          keyHostOrder.Nexthdr,
			TrafficDirection: keyHostOrder.TrafficDirection,
		}
		// Convert value to host byte-order. ToHost() makes a copy.
		entryHostOrder := value.(*policymap.PolicyEntry).ToHost()
		// Convert from policymap.PolicyEntry to policy.MapStateEntry.
		policyEntry := policy.MapStateEntry{
			ProxyPort: entryHostOrder.ProxyPort,
			IsDeny:    policymap.PolicyEntryFlags(entryHostOrder.GetFlags()).IsDeny(),
		}
		currentMap[policyKey] = policyEntry
	}
	err := e.policyMap.DumpWithCallback(cb)

	return currentMap, err
}

// syncPolicyMapWithDump attempts to synchronize the PolicyMap for this endpoint to
// contain the set of PolicyKeys represented by the endpoint's desiredMapState.
// It checks the current contents of the endpoint's PolicyMap and deletes any
// PolicyKeys that are not present in the endpoint's desiredMapState. It then
// adds any keys that are not present in the map. When a key from desiredMapState
// is inserted successfully to the endpoint's BPF PolicyMap, it is added to the
// endpoint's realizedMapState field. Returns an error if the endpoint's BPF
// PolicyMap is unable to be dumped, or any update operation to the map fails.
// Must be called with e.mutex Lock()ed.
func (e *Endpoint) syncPolicyMapWithDump() error {
	if e.policyMap == nil {
		return fmt.Errorf("not syncing PolicyMap state for endpoint because PolicyMap is nil")
	}

	// Apply pending policy map changes first so that desired map is up-to-date before
	// we diff the maps below.
	_, err := e.applyPolicyMapChanges()
	if err != nil {
		return err
	}

	currentMap, err := e.dumpPolicyMapToMapState()

	// If map is unable to be dumped, attempt to close map and open it again.
	// See GH-4229.
	if err != nil {
		e.getLogger().WithError(err).Error("unable to dump PolicyMap when trying to sync desired and realized PolicyMap state")

		// Close to avoid leaking of file descriptors, but still continue in case
		// Close() does not succeed, because otherwise the map will never be
		// opened again unless the agent is restarted.
		err := e.policyMap.Close()
		if err != nil {
			e.getLogger().WithError(err).Error("unable to close PolicyMap which was not able to be dumped")
		}

		e.policyMap, _, err = policymap.OpenOrCreate(e.policyMapPath())
		if err != nil {
			return fmt.Errorf("unable to open PolicyMap for endpoint: %s", err)
		}

		// Try to dump again, fail if error occurs.
		currentMap, err = e.dumpPolicyMapToMapState()
		if err != nil {
			return err
		}
	}

	// Log full policy map for every dump
	e.policyDebug(logrus.Fields{"dumpedPolicyMap": currentMap}, "syncPolicyMapWithDump")
	// Diffs between the maps indicate an error in the policy map update logic.
	// Collect and log diffs if policy logging is enabled.
	diffCount, diffs, err := e.syncDesiredPolicyMapWith(currentMap, e.getPolicyLogger() != nil)

	if diffCount > 0 {
		e.getLogger().WithField(logfields.Count, diffCount).Warning("Policy map sync fixed errors, consider running with debug verbose = policy to get detailed dumps")
		e.policyDebug(logrus.Fields{"dumpedDiffs": diffs}, "syncPolicyMapWithDump")
	}

	return err
}

func (e *Endpoint) syncPolicyMapController() {
	ctrlName := fmt.Sprintf("sync-policymap-%d", e.ID)
	e.controllers.UpdateController(ctrlName,
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) (reterr error) {
				// Failure to lock is not an error, it means
				// that the endpoint was disconnected and we
				// should exit gracefully.
				if err := e.lockAlive(); err != nil {
					return controller.NewExitReason("Endpoint disappeared")
				}
				defer e.unlock()
				return e.syncPolicyMapWithDump()
			},
			RunInterval: 1 * time.Minute,
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

// ValidateConnectorPlumbing checks whether the endpoint is correctly plumbed
// depending on if it is connected via veth or IPVLAN.
func (e *Endpoint) ValidateConnectorPlumbing(linkChecker linkCheckerFunc) error {
	if e.HasIpvlanDataPath() {
		// FIXME: We cannot check whether ipvlan slave netdev exists,
		// because it requires entering container netns which is not
		// always accessible (e.g. in k8s case "/proc" has to be bind
		// mounted). Instead, we check whether the tail call map exists.
		if _, err := os.Stat(e.BPFIpvlanMapPath()); err != nil {
			return fmt.Errorf("tail call map for IPvlan unavailable: %s", err)
		}
	} else {
		if linkChecker == nil {
			return fmt.Errorf("cannot check state of datapath; link checker is nil")
		}
		err := linkChecker(e.ifName)
		if err != nil {
			return fmt.Errorf("interface %s could not be found", e.ifName)
		}
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
			log.WithFields(logrus.Fields{
				logfields.URL:         "https://github.com/cilium/cilium/pull/14541",
				logfields.HelpMessage: "For more information, see the linked URL. Pass endpoint-gc-interval=\"0\" to disable",
			}).Info("Endpoint garbage collection is ineffective, ignoring endpoint")
		})
		return nil
	}
	_, err := netlink.LinkByName(iface)
	if _, ok := err.(netlink.LinkNotFoundError); ok {
		return fmt.Errorf("Endpoint is invalid: %w", err)
	}
	if err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			logfields.EndpointID:  ep.StringID(),
			logfields.ContainerID: ep.GetShortContainerID(),
			logfields.K8sPodName:  ep.GetK8sNamespaceAndPodName(),
		}).Warning("An error occurred while checking endpoint health")
	}
	return nil
}
