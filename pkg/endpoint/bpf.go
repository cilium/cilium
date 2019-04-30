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
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/loadinfo"
	"github.com/cilium/cilium/pkg/logging/logfields"
	bpfconfig "github.com/cilium/cilium/pkg/maps/configmap"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/eppolicymap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/version"

	"github.com/sirupsen/logrus"
)

const (
	// EndpointGenerationTimeout specifies timeout for proxy completion context
	EndpointGenerationTimeout = 330 * time.Second
)

// PolicyMapPathLocked returns the path to the policy map of endpoint.
func (e *Endpoint) PolicyMapPathLocked() string {
	return bpf.LocalMapPath(policymap.MapName, e.ID)
}

// CallsMapPathLocked returns the path to cilium tail calls map of an endpoint.
func (e *Endpoint) CallsMapPathLocked() string {
	return bpf.LocalMapPath(loader.CallsMapName, e.ID)
}

// BPFConfigMapPath returns the path to the BPF config map of endpoint.
func (e *Endpoint) BPFConfigMapPath() string {
	return bpf.LocalMapPath(bpfconfig.MapNamePrefix, e.ID)
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
func (e *Endpoint) writeInformationalComments(w io.Writer, owner Owner) error {
	fw := bufio.NewWriter(w)

	fmt.Fprint(fw, "/*\n")

	epStr64, err := e.base64()
	if err == nil {
		var verBase64 string
		verBase64, err = version.Base64()
		if err == nil {
			fmt.Fprintf(fw, " * %s%s:%s\n * \n", common.CiliumCHeaderPrefix,
				verBase64, epStr64)
		}
	}
	if err != nil {
		e.logStatusLocked(BPF, Warning, fmt.Sprintf("Unable to create a base64: %s", err))
	}

	if e.ContainerID == "" {
		fmt.Fprintf(fw, " * Docker Network ID: %s\n", e.DockerNetworkID)
		fmt.Fprintf(fw, " * Docker Endpoint ID: %s\n", e.DockerEndpointID)
	} else {
		fmt.Fprintf(fw, " * Container ID: %s\n", e.ContainerID)
	}

	fmt.Fprintf(fw, ""+
		" * IPv6 address: %s\n"+
		" * IPv4 address: %s\n"+
		" * Identity: %d\n"+
		" * PolicyMap: %s\n"+
		" * NodeMAC: %s\n"+
		" */\n\n",
		e.IPv6.String(), e.IPv4.String(),
		e.GetIdentity(), path.Base(e.PolicyMapPathLocked()),
		e.NodeMAC)

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

func (e *Endpoint) writeHeaderfile(prefix string, owner Owner) error {
	headerPath := filepath.Join(prefix, common.CHeaderFileName)
	e.getLogger().WithFields(logrus.Fields{
		logfields.Path: headerPath,
	}).Debug("writing header file")
	f, err := os.Create(headerPath)
	if err != nil {
		return fmt.Errorf("failed to open file %s for writing: %s", headerPath, err)

	}
	defer f.Close()

	if err = e.writeInformationalComments(f, owner); err != nil {
		return err
	}
	return owner.Datapath().WriteEndpointConfig(f, e)
}

// addNewRedirectsFromMap must be called while holding the endpoint lock for
// writing. On success, returns nil; otherwise, returns an error  indicating the
// problem that occurred while adding an l7 redirect for the specified policy.
// Must be called with endpoint.Mutex held.
func (e *Endpoint) addNewRedirectsFromMap(owner Owner, m policy.L4PolicyMap, desiredRedirects map[string]bool, proxyWaitGroup *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc) {
	if option.Config.DryMode {
		return nil, nil, nil
	}

	var finalizeList revert.FinalizeList
	var revertStack revert.RevertStack
	var updatedStats []*models.ProxyStatistics
	insertedDesiredMapState := make(map[policy.Key]struct{})
	updatedDesiredMapState := make(policy.MapState)

	for _, l4 := range m {
		if l4.IsRedirect() {
			var redirectPort uint16
			var err error
			// Only create a redirect if the proxy is NOT running in a sidecar
			// container. If running in a sidecar container, just allow traffic
			// to the port at L4 by setting the proxy port to 0.
			if !e.hasSidecarProxy || l4.L7Parser != policy.ParserTypeHTTP {
				var finalizeFunc revert.FinalizeFunc
				var revertFunc revert.RevertFunc
				redirectPort, err, finalizeFunc, revertFunc = owner.UpdateProxyRedirect(e, &l4, proxyWaitGroup)
				if err != nil {
					revertStack.Revert() // Ignore errors while reverting. This is best-effort.
					return err, nil, nil
				}
				finalizeList.Append(finalizeFunc)
				revertStack.Push(revertFunc)

				proxyID := e.ProxyID(&l4)
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
				proxyStats := e.getProxyStatisticsLocked(string(l4.L7Parser), uint16(l4.Port), l4.Ingress)
				proxyStats.AllocatedProxyPort = int64(redirectPort)
				e.proxyStatisticsMutex.Unlock()

				updatedStats = append(updatedStats, proxyStats)
			}

			// Set the proxy port in the policy map.
			var direction trafficdirection.TrafficDirection
			if l4.Ingress {
				direction = trafficdirection.Ingress
			} else {
				direction = trafficdirection.Egress
			}

			keysFromFilter := l4.ToKeys(direction, *e.prevIdentityCache)

			for _, keyFromFilter := range keysFromFilter {
				if oldEntry, ok := e.desiredPolicy.PolicyMapState[keyFromFilter]; ok {
					updatedDesiredMapState[keyFromFilter] = oldEntry
				} else {
					insertedDesiredMapState[keyFromFilter] = struct{}{}
				}

				e.desiredPolicy.PolicyMapState[keyFromFilter] = policy.MapStateEntry{ProxyPort: redirectPort}
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

// addNewRedirects must be called while holding the endpoint lock for writing.
// On success, returns nil; otherwise, returns an error indicating the problem
// that occurred while adding an l7 redirect for the specified policy.
// The returned map contains the exact set of IDs of proxy redirects that is
// required to implement the given L4 policy.
// Must be called with endpoint.Mutex held.
func (e *Endpoint) addNewRedirects(owner Owner, m *policy.L4Policy, proxyWaitGroup *completion.WaitGroup) (desiredRedirects map[string]bool, err error, finalizeFunc revert.FinalizeFunc, revertFunc revert.RevertFunc) {
	desiredRedirects = make(map[string]bool)
	var finalizeList revert.FinalizeList
	var revertStack revert.RevertStack

	var ff revert.FinalizeFunc
	var rf revert.RevertFunc

	err, ff, rf = e.addNewRedirectsFromMap(owner, m.Ingress, desiredRedirects, proxyWaitGroup)
	if err != nil {
		return desiredRedirects, fmt.Errorf("unable to allocate ingress redirects: %s", err), nil, nil
	}
	finalizeList.Append(ff)
	revertStack.Push(rf)

	err, ff, rf = e.addNewRedirectsFromMap(owner, m.Egress, desiredRedirects, proxyWaitGroup)
	if err != nil {
		revertStack.Revert() // Ignore errors while reverting. This is best-effort.
		return desiredRedirects, fmt.Errorf("unable to allocate egress redirects: %s", err), nil, nil
	}
	finalizeList.Append(ff)
	revertStack.Push(rf)

	return desiredRedirects, nil, finalizeList.Finalize, func() error {
		e.getLogger().Debug("Reverting proxy redirect additions")

		err := revertStack.Revert()

		e.getLogger().Debug("Finished reverting proxy redirect additions")

		return err
	}
}

// Must be called with endpoint.Mutex held.
func (e *Endpoint) removeOldRedirects(owner Owner, desiredRedirects map[string]bool, proxyWaitGroup *completion.WaitGroup) (revert.FinalizeFunc, revert.RevertFunc) {
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

		err, finalizeFunc, revertFunc := owner.RemoveProxyRedirect(e, id, proxyWaitGroup)
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
		//
		// We don't know the L7 protocol of the redirect, so we can't just
		// build a ProxyStatistics and lookup e.proxyStatistics by key.
		// We have to loop to find which entry has the same redirect port.
		// Looping is acceptable since there should be only a few redirects
		// for each endpoint.
		e.proxyStatisticsMutex.Lock()
		for _, stats := range e.proxyStatistics {
			if stats.AllocatedProxyPort == int64(redirectPort) {
				updatedStats[redirectPort] = stats
				stats.AllocatedProxyPort = 0
				break
			}
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
// Must be called with endpoint.Mutex not held and endpoint.BuildMutex held.
// Returns the policy revision number when the regeneration has called, a
// boolean if the BPF compilation was executed and an error in case of an error.
func (e *Endpoint) regenerateBPF(owner Owner, regenContext *regenerationContext) (revnum uint64, compiled bool, reterr error) {
	var (
		err                 error
		compilationExecuted bool
	)

	stats := &regenContext.Stats
	stats.waitingForLock.Start()

	datapathRegenCtxt := regenContext.datapathRegenerationContext

	// Make sure that owner is not compiling base programs while we are
	// regenerating an endpoint.
	owner.GetCompilationLock().RLock()
	stats.waitingForLock.End(true)
	defer owner.GetCompilationLock().RUnlock()

	datapathRegenCtxt.prepareForProxyUpdates(regenContext.parentContext)
	defer datapathRegenCtxt.completionCancel()

	err = e.runPreCompilationSteps(owner, regenContext)

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

	// Hook the endpoint into the endpoint and endpoint to policy tables then expose it
	stats.mapSync.Start()
	epErr := eppolicymap.WriteEndpoint(datapathRegenCtxt.epInfoCache.keys, e.PolicyMap)
	err = lxcmap.WriteEndpoint(datapathRegenCtxt.epInfoCache)
	stats.mapSync.End(err == nil)
	if epErr != nil {
		e.logStatusLocked(BPF, Warning, fmt.Sprintf("Unable to sync EpToPolicy Map continue with Sockmap support: %s", epErr))
	}
	if err != nil {
		return 0, compilationExecuted, fmt.Errorf("Exposing new BPF failed: %s", err)
	}

	// Signal that BPF program has been generated.
	// The endpoint has at least L3/L4 connectivity at this point.
	e.CloseBPFProgramChannel()

	// Allow another builder to start while we wait for the proxy
	if regenContext.DoneFunc != nil {
		regenContext.DoneFunc()
	}

	stats.proxyWaitForAck.Start()
	err = e.WaitForProxyCompletions(datapathRegenCtxt.proxyWaitGroup)
	stats.proxyWaitForAck.End(err == nil)
	if err != nil {
		return 0, compilationExecuted, fmt.Errorf("Error while configuring proxy redirects: %s", err)
	}

	stats.waitingForLock.Start()
	err = e.LockAlive()
	stats.waitingForLock.End(err == nil)
	if err != nil {
		return 0, compilationExecuted, err
	}
	defer e.Unlock()

	e.ctCleaned = true

	// Synchronously try to update PolicyMap for this endpoint. If any
	// part of updating the PolicyMap fails, bail out and do not generate
	// BPF. Unfortunately, this means that the map will be in an inconsistent
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

	return datapathRegenCtxt.epInfoCache.revision, compilationExecuted, err
}

func (e *Endpoint) realizeBPFState(regenContext *regenerationContext) (compilationExecuted bool, err error) {
	stats := &regenContext.Stats
	datapathRegenCtxt := regenContext.datapathRegenerationContext

	e.getLogger().WithField(fieldRegenLevel, datapathRegenCtxt.regenerationLevel).Debug("Preparing to compile BPF")

	if datapathRegenCtxt.regenerationLevel > RegenerateWithoutDatapath {
		closeChan := loadinfo.LogPeriodicSystemLoad(log.WithFields(logrus.Fields{logfields.EndpointID: e.StringID()}).Debugf, time.Second)

		// Compile and install BPF programs for this endpoint
		if datapathRegenCtxt.regenerationLevel == RegenerateWithDatapathRebuild {
			err = loader.CompileAndLoad(datapathRegenCtxt.completionCtx, datapathRegenCtxt.epInfoCache, &stats.datapathRealization)
			e.getLogger().WithError(err).Info("Regenerated endpoint BPF program")
			compilationExecuted = true
		} else if datapathRegenCtxt.regenerationLevel == RegenerateWithDatapathRewrite {
			err = loader.CompileOrLoad(datapathRegenCtxt.completionCtx, datapathRegenCtxt.epInfoCache, &stats.datapathRealization)
			if err == nil {
				e.getLogger().Info("Rewrote endpoint BPF program")
			} else {
				e.getLogger().WithError(err).Error("Error while rewriting endpoint BPF program")
			}
			compilationExecuted = true
		} else { // RegenerateWithDatapathLoad
			err = loader.ReloadDatapath(datapathRegenCtxt.completionCtx, datapathRegenCtxt.epInfoCache, &stats.datapathRealization)
			if err == nil {
				e.getLogger().Info("Reloaded endpoint BPF program")
			} else {
				e.getLogger().WithError(err).Error("Error while reloading endpoint BPF program")
			}
		}
		close(closeChan)

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
func (e *Endpoint) runPreCompilationSteps(owner Owner, regenContext *regenerationContext) (preCompilationError error) {
	stats := &regenContext.Stats
	datapathRegenCtxt := regenContext.datapathRegenerationContext

	stats.waitingForLock.Start()
	err := e.LockAlive()
	stats.waitingForLock.End(err == nil)
	if err != nil {
		return err
	}

	defer e.Unlock()

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
				created := ctmap.Exists(nil, ipv4, ipv6)
				if e.ConntrackLocal() {
					created = ctmap.Exists(e, ipv4, ipv6)
				}
				if created {
					e.scrubIPsInConntrackTable()
				}
			}
			close(datapathRegenCtxt.ctCleaned)
		}()
	} else {
		close(datapathRegenCtxt.ctCleaned)
	}

	if e.realizedPolicy == nil {
		e.realizedPolicy = &policy.EndpointPolicy{}
	}

	// If dry mode is enabled, no further changes to BPF maps are performed
	if option.Config.DryMode {

		// Compute policy for this endpoint.
		if err = e.regeneratePolicy(owner); err != nil {
			return fmt.Errorf("Unable to regenerate policy: %s", err)
		}

		_ = e.updateAndOverrideEndpointOptions(nil)

		// Dry mode needs Network Policy Updates, but the proxy wait group must
		// not be initialized, as there is no proxy ACKing the changes.
		if err, _ = e.updateNetworkPolicy(owner, nil); err != nil {
			return err
		}

		if err = e.writeHeaderfile(nextDir, owner); err != nil {
			return fmt.Errorf("Unable to write header file: %s", err)
		}

		log.WithField(logfields.EndpointID, e.ID).Debug("Skipping bpf updates due to dry mode")
		return nil
	}

	if e.PolicyMap == nil {
		e.PolicyMap, _, err = policymap.OpenOrCreate(e.PolicyMapPathLocked())
		if err != nil {
			return err
		}
		// Clean up map contents
		e.getLogger().Debug("flushing old PolicyMap")
		err = e.PolicyMap.DeleteAll()
		if err != nil {
			return err
		}

		// Also reset the in-memory state of the realized state as the
		// BPF map content is guaranteed to be empty right now.
		e.realizedPolicy.PolicyMapState = make(policy.MapState)
	}

	if e.bpfConfigMap == nil {
		e.bpfConfigMap, _, err = bpfconfig.OpenMapWithName(e.BPFConfigMapPath())
		if err != nil {
			return err
		}
		// Also reset the in-memory state of the realized state as the
		// BPF map content is guaranteed to be empty right now.
		e.realizedBPFConfig = &bpfconfig.EndpointConfig{}
	}

	// Only generate & populate policy map if a security identity is set up for
	// this endpoint.
	if e.SecurityIdentity != nil {
		stats.policyCalculation.Start()
		err = e.regeneratePolicy(owner)
		stats.policyCalculation.End(err == nil)
		if err != nil {
			return fmt.Errorf("unable to regenerate policy for '%s': %s", e.PolicyMap.String(), err)
		}

		_ = e.updateAndOverrideEndpointOptions(nil)

		// realizedBPFConfig may be updated at any point after we figure out
		// whether ingress/egress policy is enabled.
		e.desiredBPFConfig = bpfconfig.GetConfig(e)

		// Synchronously try to update PolicyMap for this endpoint. If any
		// part of updating the PolicyMap fails, bail out and do not generate
		// BPF. Unfortunately, this means that the map will be in an inconsistent
		// state with the current program (if it exists) for this endpoint.
		// GH-3897 would fix this by creating a new map to do an atomic swap
		// with the old one.
		stats.mapSync.Start()
		err := e.syncPolicyMap()
		stats.mapSync.End(err == nil)
		if err != nil {
			return fmt.Errorf("unable to regenerate policy because PolicyMap synchronization failed: %s", err)
		}

		// Synchronously update the BPF ConfigMap for this endpoint.
		// This is unlikely to fail, but will have the same
		// inconsistency issues as above if there is a failure. Long
		// term the solution to this is to templatize this map in the
		// ELF file, but there's no solution to this just yet.
		if err = e.bpfConfigMap.Update(e.desiredBPFConfig); err != nil {
			e.getLogger().WithError(err).Error("unable to update BPF config map")
			return err
		}

		datapathRegenCtxt.revertStack.Push(func() error {
			return e.bpfConfigMap.Update(e.realizedBPFConfig)
		})

		// Configure the new network policy with the proxies.
		stats.proxyPolicyCalculation.Start()
		var networkPolicyRevertFunc revert.RevertFunc
		err, networkPolicyRevertFunc = e.updateNetworkPolicy(owner, datapathRegenCtxt.proxyWaitGroup)
		stats.proxyPolicyCalculation.End(err == nil)
		if err != nil {
			return err
		}

		datapathRegenCtxt.revertStack.Push(networkPolicyRevertFunc)
	}

	stats.proxyConfiguration.Start()
	var finalizeFunc revert.FinalizeFunc
	var revertFunc revert.RevertFunc
	// Walk the L4Policy to add new redirects and update the desired policy map
	// state to set the newly allocated proxy ports.
	var desiredRedirects map[string]bool
	if e.desiredPolicy != nil && e.desiredPolicy.L4Policy != nil {
		desiredRedirects, err, finalizeFunc, revertFunc = e.addNewRedirects(owner, e.desiredPolicy.L4Policy, datapathRegenCtxt.proxyWaitGroup)
		if err != nil {
			stats.proxyConfiguration.End(false)
			return err
		}
		datapathRegenCtxt.finalizeList.Append(finalizeFunc)
		datapathRegenCtxt.revertStack.Push(revertFunc)
	}

	// At this point, traffic is no longer redirected to the proxy for
	// now-obsolete redirects, since we synced the updated policy map above.
	// It's now safe to remove the redirects from the proxy's configuration.
	finalizeFunc, revertFunc = e.removeOldRedirects(owner, desiredRedirects, datapathRegenCtxt.proxyWaitGroup)
	datapathRegenCtxt.finalizeList.Append(finalizeFunc)
	datapathRegenCtxt.revertStack.Push(revertFunc)
	stats.proxyConfiguration.End(true)

	stats.prepareBuild.Start()
	defer func() {
		stats.prepareBuild.End(preCompilationError == nil)
	}()

	// Generate header file specific to this endpoint for use in compiling
	// BPF programs for this endpoint.
	if err = e.writeHeaderfile(nextDir, owner); err != nil {
		return fmt.Errorf("unable to write header file: %s", err)
	}

	// Avoid BPF program compilation and installation if the headerfile for the endpoint
	// or the node have not changed.
	datapathRegenCtxt.bpfHeaderfilesHash, err = loader.EndpointHash(e)
	if err != nil {
		e.getLogger().WithError(err).Warn("Unable to hash header file")
		datapathRegenCtxt.bpfHeaderfilesHash = ""
		datapathRegenCtxt.regenerationLevel = RegenerateWithDatapathRewrite
	} else {
		changed := (datapathRegenCtxt.bpfHeaderfilesHash != e.bpfHeaderfileHash)
		if changed {
			datapathRegenCtxt.regenerationLevel = RegenerateWithDatapathRewrite
		}
		e.getLogger().WithField(logfields.BPFHeaderfileHash, datapathRegenCtxt.bpfHeaderfilesHash).
			Debugf("BPF header file hashed (was: %q)", e.bpfHeaderfileHash)
	}

	// Cache endpoint information so that we can release the endpoint lock.
	if datapathRegenCtxt.regenerationLevel >= RegenerateWithDatapathRewrite {
		datapathRegenCtxt.epInfoCache = e.createEpInfoCache(nextDir)
	} else {
		datapathRegenCtxt.epInfoCache = e.createEpInfoCache(currentDir)
	}
	if datapathRegenCtxt.epInfoCache == nil {
		return fmt.Errorf("Unable to cache endpoint information")
	}

	return nil
}

func (e *Endpoint) finalizeProxyState(regenContext *regenerationContext, err error) {
	datapathRegenCtx := regenContext.datapathRegenerationContext
	if err == nil {
		// Always execute the finalization code, even if the endpoint is
		// terminating, in order to properly release resources.
		e.UnconditionalLock()
		e.getLogger().Debug("Finalizing successful endpoint regeneration")
		datapathRegenCtx.finalizeList.Finalize()
		e.Unlock()
	} else {
		if err := e.LockAlive(); err != nil {
			e.getLogger().WithError(err).Debug("Skipping unnecessary reverting of endpoint regeneration changes")
			return
		}
		e.getLogger().Debug("Reverting endpoint changes after BPF regeneration failed")
		if err := datapathRegenCtx.revertStack.Revert(); err != nil {
			e.getLogger().WithError(err).Error("Reverting endpoint regeneration changes failed")
		}
		e.getLogger().Debug("Finished reverting endpoint changes after BPF regeneration failed")
		e.Unlock()
	}
}

// DeleteMapsLocked releases references to all BPF maps associated with this
// endpoint.
//
// For each error that occurs while releasing these references, an error is
// added to the resulting error slice which is returned.
//
// Returns nil on success.
func (e *Endpoint) DeleteMapsLocked() []error {
	var errors []error

	maps := map[string]string{
		"config": e.BPFConfigMapPath(),
		"policy": e.PolicyMapPathLocked(),
		"calls":  e.CallsMapPathLocked(),
		"egress": e.BPFIpvlanMapPath(),
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

	return errors
}

// DeleteBPFProgramLocked delete the BPF program associated with the endpoint's
// veth interface.
func (e *Endpoint) DeleteBPFProgramLocked() error {
	e.getLogger().Debug("deleting bpf program from endpoint")
	return loader.DeleteDatapath(context.TODO(), e.IfName, "ingress")
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
	e.UnconditionalLock()
	e.scrubIPsInConntrackTableLocked()
	e.Unlock()
}

// SkipStateClean can be called on a endpoint before its first build to skip
// the cleaning of state such as the conntrack table. This is useful when an
// endpoint is being restored from state and the datapath state should not be
// claned.
//
// The endpoint lock must NOT be held.
func (e *Endpoint) SkipStateClean() {
	// Mark conntrack as already cleaned
	e.UnconditionalLock()
	e.ctCleaned = true
	e.Unlock()
}

// GetBPFKeys returns all keys which should represent this endpoint in the BPF
// endpoints map
func (e *Endpoint) GetBPFKeys() []*lxcmap.EndpointKey {
	keys := []*lxcmap.EndpointKey{}
	if e.IPv6.IsSet() {
		keys = append(keys, lxcmap.NewEndpointKey(e.IPv6.IP()))
	}

	if e.IPv4.IsSet() {
		keys = append(keys, lxcmap.NewEndpointKey(e.IPv4.IP()))
	}

	return keys
}

// GetBPFValue returns the value which should represent this endpoint in the
// BPF endpoints map
func (e *Endpoint) GetBPFValue() (*lxcmap.EndpointInfo, error) {
	mac, err := e.LXCMAC.Uint64()
	if err != nil {
		return nil, fmt.Errorf("invalid LXC MAC: %v", err)
	}

	nodeMAC, err := e.NodeMAC.Uint64()
	if err != nil {
		return nil, fmt.Errorf("invalid node MAC: %v", err)
	}

	info := &lxcmap.EndpointInfo{
		IfIndex: uint32(e.IfIndex),
		// Store security identity in network byte order so it can be
		// written into the packet without an additional byte order
		// conversion.
		LxcID:   e.ID,
		MAC:     lxcmap.MAC(mac),
		NodeMAC: lxcmap.MAC(nodeMAC),
	}

	return info, nil
}

// syncPolicyMap attempts to synchronize the PolicyMap for this endpoint to
// contain the set of PolicyKeys represented by the endpoint's desiredMapState.
// It checks the current contents of the endpoint's PolicyMap and deletes any
// PolicyKeys that are not present in the endpoint's desiredMapState. It then
// adds any keys that are not present in the map. When a key from desiredMapState
// is inserted successfully to the endpoint's BPF PolicyMap, it is added to the
// endpoint's realizedMapState field. Returns an error if the endpoint's BPF
// PolicyMap is unable to be dumped, or any update operation to the map fails.
// Must be called with e.Mutex locked.
func (e *Endpoint) syncPolicyMap() error {

	if e.realizedPolicy.PolicyMapState == nil {
		e.realizedPolicy.PolicyMapState = make(policy.MapState)
	}

	if e.desiredPolicy.PolicyMapState == nil {
		e.desiredPolicy.PolicyMapState = make(policy.MapState)
	}

	if e.PolicyMap == nil {
		return fmt.Errorf("not syncing PolicyMap state for endpoint because PolicyMap is nil")
	}

	currentMapContents, err := e.PolicyMap.DumpToSlice()

	// If map is unable to be dumped, attempt to close map and open it again.
	// See GH-4229.
	if err != nil {
		e.getLogger().WithError(err).Error("unable to dump PolicyMap when trying to sync desired and realized PolicyMap state")

		// Close to avoid leaking of file descriptors, but still continue in case
		// Close() does not succeed, because otherwise the map will never be
		// opened again unless the agent is restarted.
		err := e.PolicyMap.Close()
		if err != nil {
			e.getLogger().WithError(err).Error("unable to close PolicyMap which was not able to be dumped")
		}

		e.PolicyMap, _, err = policymap.OpenOrCreate(e.PolicyMapPathLocked())
		if err != nil {
			return fmt.Errorf("unable to open PolicyMap for endpoint: %s", err)
		}

		// Try to dump again, fail if error occurs.
		currentMapContents, err = e.PolicyMap.DumpToSlice()
		if err != nil {
			return err
		}
	}

	errors := []error{}

	for _, entry := range currentMapContents {
		// Convert key to host-byte order for lookup in the desiredMapState.
		keyHostOrder := entry.Key.ToHost()

		// Convert from policymap.Key to policy.Key
		policyMapKeyToPolicyKey := policy.Key{
			Identity:         keyHostOrder.Identity,
			DestPort:         keyHostOrder.DestPort,
			Nexthdr:          keyHostOrder.Nexthdr,
			TrafficDirection: keyHostOrder.TrafficDirection,
		}

		// If key that is in policy map is not in desired state, just remove it.
		if _, ok := e.desiredPolicy.PolicyMapState[policyMapKeyToPolicyKey]; !ok {
			// Can pass key with host byte-order fields, as it will get
			// converted to network byte-order.
			err := e.PolicyMap.DeleteKey(keyHostOrder)
			if err != nil {
				e.getLogger().WithError(err).Errorf("Failed to delete PolicyMap key %s", entry.Key.String())
				errors = append(errors, err)
			} else {
				// Operation was successful, remove from realized state.
				delete(e.realizedPolicy.PolicyMapState, policyMapKeyToPolicyKey)
			}
		}
	}

	for keyToAdd, entry := range e.desiredPolicy.PolicyMapState {
		if oldEntry, ok := e.realizedPolicy.PolicyMapState[keyToAdd]; !ok || oldEntry != entry {

			// Convert from policy.Key to policymap.Key
			policyKeyToPolicyMapKey := policymap.PolicyKey{
				Identity:         keyToAdd.Identity,
				DestPort:         keyToAdd.DestPort,
				Nexthdr:          keyToAdd.Nexthdr,
				TrafficDirection: keyToAdd.TrafficDirection,
			}

			err := e.PolicyMap.AllowKey(policyKeyToPolicyMapKey, entry.ProxyPort)
			if err != nil {
				e.getLogger().WithError(err).Errorf("Failed to add PolicyMap key %s %d", policyKeyToPolicyMapKey.String(), entry.ProxyPort)
				errors = append(errors, err)
			} else {
				// Operation was successful, add to realized state.
				e.realizedPolicy.PolicyMapState[keyToAdd] = entry
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("synchronizing desired PolicyMap state failed: %s", errors)
	}

	return nil
}

func (e *Endpoint) syncPolicyMapController() {
	ctrlName := fmt.Sprintf("sync-policymap-%d", e.ID)
	e.controllers.UpdateController(ctrlName,
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) (reterr error) {
				// Failure to lock is not an error, it means
				// that the endpoint was disconnected and we
				// should exit gracefully.
				if err := e.LockAlive(); err != nil {
					return controller.NewExitReason("Endpoint disappeared")
				}
				defer e.Unlock()
				return e.syncPolicyMap()
			},
			RunInterval: 1 * time.Minute,
		},
	)
}
