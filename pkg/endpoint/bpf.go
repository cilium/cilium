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
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/loadinfo"
	"github.com/cilium/cilium/pkg/logging/logfields"
	bpfconfig "github.com/cilium/cilium/pkg/maps/configmap"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/version"

	"github.com/sirupsen/logrus"
)

const (
	// ExecTimeout is the execution timeout to use in join_ep.sh executions
	ExecTimeout = 300 * time.Second

	// EndpointGenerationTimeout specifies timeout for proxy completion context
	EndpointGenerationTimeout = 55 * time.Second
)

// BPFConfigMapPath returns the path to the BPF config map of endpoint.
func (e *Endpoint) BPFConfigMapPath() string {
	return bpf.MapPath(e.BPFConfigMapName())
}

// BPFConfigMapName returns the name of the config map for endpoint.
func (e *Endpoint) BPFConfigMapName() string {
	return bpfconfig.MapNamePrefix + strconv.Itoa(int(e.ID))
}

type getBPFDataCallback func() (s6, s4 []int)

// WriteIPCachePrefixes fetches the set of prefixes that should be used from
// the specified getBPFData function, and writes the IPCache prefixes to the
// given writer in the format that the datapath expects.
func WriteIPCachePrefixes(fw *bufio.Writer, getBPFData getBPFDataCallback) {
	// In case the Linux kernel doesn't support LPM map type, pass the set of
	// prefix length for the datapath to lookup the map.
	if ipcache.IPCache.MapType != bpf.BPF_MAP_TYPE_LPM_TRIE {
		ipcachePrefixes6, ipcachePrefixes4 := policy.GetDefaultPrefixLengths()
		if getBPFData != nil {
			// This will include the default prefix lengths from above.
			ipcachePrefixes6, ipcachePrefixes4 = getBPFData()
		}

		fw.WriteString("#define IPCACHE6_PREFIXES ")
		for _, prefix := range ipcachePrefixes6 {
			fmt.Fprintf(fw, "%d,", prefix)
		}
		fw.WriteString("\n")
		fw.WriteString("#define IPCACHE4_PREFIXES ")
		for _, prefix := range ipcachePrefixes4 {
			fmt.Fprintf(fw, "%d,", prefix)
		}
		fw.WriteString("\n")
	}
}

func (e *Endpoint) writeHeaderfile(prefix string, owner Owner) error {
	headerPath := filepath.Join(prefix, common.CHeaderFileName)
	f, err := os.Create(headerPath)
	if err != nil {
		return fmt.Errorf("failed to open file %s for writing: %s", headerPath, err)

	}
	defer f.Close()

	fw := bufio.NewWriter(f)

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
		" * MAC: %s\n"+
		" * IPv6 address: %s\n"+
		" * IPv4 address: %s\n"+
		" * Identity: %d\n"+
		" * PolicyMap: %s\n"+
		" * IPv6 Ingress Map: %s\n"+
		" * IPv6 Egress Map: %s\n"+
		" * IPv4 Ingress Map: %s\n"+
		" * IPv4 Egress Map: %s\n"+
		" * NodeMAC: %s\n"+
		" */\n\n",
		e.LXCMAC, e.IPv6.String(), e.IPv4.String(),
		e.GetIdentity(), path.Base(e.PolicyMapPathLocked()),
		path.Base(e.IPv6IngressMapPathLocked()),
		path.Base(e.IPv6EgressMapPathLocked()),
		path.Base(e.IPv4IngressMapPathLocked()),
		path.Base(e.IPv4EgressMapPathLocked()),
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

	fw.WriteString(common.FmtDefineAddress("LXC_MAC", e.LXCMAC))
	fw.WriteString(common.FmtDefineComma("LXC_IP", e.IPv6))
	if e.IPv4 != nil {
		fmt.Fprintf(fw, "#define LXC_IPV4 %#x\n", byteorder.HostSliceToNetwork(e.IPv4, reflect.Uint32))
	}
	fw.WriteString(common.FmtDefineAddress("NODE_MAC", e.NodeMAC))
	fmt.Fprintf(fw, "#define LXC_ID %#x\n", e.ID)
	fmt.Fprintf(fw, "#define LXC_ID_NB %#x\n", byteorder.HostToNetwork(e.ID))
	if e.SecurityIdentity != nil {
		fmt.Fprintf(fw, "#define SECLABEL %s\n", e.SecurityIdentity.ID.StringID())
		fmt.Fprintf(fw, "#define SECLABEL_NB %#x\n", byteorder.HostToNetwork(e.SecurityIdentity.ID.Uint32()))
	} else {
		invalid := identity.InvalidIdentity
		fmt.Fprintf(fw, "#define SECLABEL %s\n", invalid.StringID())
		fmt.Fprintf(fw, "#define SECLABEL_NB %#x\n", byteorder.HostToNetwork(invalid.Uint32()))
	}
	fmt.Fprintf(fw, "#define POLICY_MAP %s\n", path.Base(e.PolicyMapPathLocked()))
	fmt.Fprintf(fw, "#define CALLS_MAP %s\n", path.Base(e.CallsMapPathLocked()))
	fmt.Fprintf(fw, "#define CONFIG_MAP %s\n", path.Base(e.BPFConfigMapPath()))
	if e.ConntrackLocalLocked() {
		ctmap.WriteBPFMacros(fw, e)
	} else {
		ctmap.WriteBPFMacros(fw, nil)
	}

	// Always enable L4 and L3 load balancer for now
	fw.WriteString("#define LB_L3\n")
	fw.WriteString("#define LB_L4\n")

	// Endpoint options
	fw.WriteString(e.Options.GetFmtList())

	if e.L3Policy == nil {
		WriteIPCachePrefixes(fw, nil)
	} else {
		WriteIPCachePrefixes(fw, e.L3Policy.ToBPFData)
	}

	return fw.Flush()
}

// hashEndpointHeaderFiles returns the MD5 hash of any header files that are
// used in the compilation of an endpoint's BPF program. Currently, this
// includes the endpoint's headerfile, and the node's headerfile.
func hashEndpointHeaderfiles(prefix string) (string, error) {
	endpointHeaderPath := filepath.Join(prefix, common.CHeaderFileName)
	hashWriter := md5.New()
	hashWriter, err := hashHeaderfile(hashWriter, endpointHeaderPath)
	if err != nil {
		return "", err
	}

	hashWriter, err = hashHeaderfile(hashWriter, option.Config.GetNodeConfigPath())
	if err != nil {
		return "", err
	}

	combinedHeaderHashSum := hashWriter.Sum(nil)
	return hex.EncodeToString(combinedHeaderHashSum[:]), nil
}

// hashHeaderfile returns the hash of the BPF headerfile at the given filepath.
// This ignores all lines that don't start with "#", incl. all comments, since
// they have no effect on the BPF compilation.
func hashHeaderfile(hashWriter hash.Hash, filepath string) (hash.Hash, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	firstFragmentOfLine := true
	lineToHash := false
	for {
		fragment, isPrefix, err := reader.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if firstFragmentOfLine && len(fragment) > 0 && fragment[0] == '#' {
			lineToHash = true
		}
		if lineToHash {
			hashWriter.Write(fragment)
		}
		firstFragmentOfLine = !isPrefix
		if firstFragmentOfLine {
			// The next fragment is the beginning of a new line.
			lineToHash = false
		}
	}

	return hashWriter, nil
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
	insertedDesiredMapState := make(map[policymap.PolicyKey]struct{})
	updatedDesiredMapState := make(PolicyMapState)

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
			var direction policymap.TrafficDirection
			if l4.Ingress {
				direction = policymap.Ingress
			} else {
				direction = policymap.Egress
			}
			keysFromFilter := e.convertL4FilterToPolicyMapKeys(&l4, direction)
			for _, keyFromFilter := range keysFromFilter {
				if oldEntry, ok := e.desiredMapState[keyFromFilter]; ok {
					updatedDesiredMapState[keyFromFilter] = oldEntry
				} else {
					insertedDesiredMapState[keyFromFilter] = struct{}{}
				}

				e.desiredMapState[keyFromFilter] = PolicyMapStateEntry{ProxyPort: redirectPort}
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
			delete(e.desiredMapState, key)
		}
		for key, entry := range updatedDesiredMapState {
			e.desiredMapState[key] = entry
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
func (e *Endpoint) regenerateBPF(owner Owner, currentDir, nextDir string, regenContext *RegenerationContext, reloadDatapath bool) (revnum uint64, compiled bool, reterr error) {
	var (
		err                 error
		compilationExecuted bool
	)

	stats := &regenContext.Stats
	stats.waitingForLock.Start()

	// Make sure that owner is not compiling base programs while we are
	// regenerating an endpoint.
	owner.GetCompilationLock().RLock()
	defer owner.GetCompilationLock().RUnlock()

	ctCleaned := make(chan struct{})

	err = e.LockAlive()
	stats.waitingForLock.End(err == nil)
	if err != nil {
		return 0, compilationExecuted, err
	}

	epID := e.StringID()

	// In the first ever regeneration of the endpoint, the conntrack table
	// is cleaned from the new endpoint IPs as it is guaranteed that any
	// pre-existing connections using that IP are now invalid.
	if !e.ctCleaned {
		go func() {
			ipv4 := !option.Config.IPv4Disabled
			created := ctmap.Exists(nil, ipv4, true)
			if e.ConntrackLocal() {
				created = ctmap.Exists(e, ipv4, true)
			}
			if created {
				e.scrubIPsInConntrackTable()
			}
			close(ctCleaned)
		}()
	} else {
		close(ctCleaned)
	}

	// If dry mode is enabled, no further changes to BPF maps are performed
	if option.Config.DryMode {
		defer e.Unlock()

		// Compute policy for this endpoint.
		if err = e.regeneratePolicy(owner); err != nil {
			return 0, compilationExecuted, fmt.Errorf("Unable to regenerate policy: %s", err)
		}

		_ = e.updateAndOverrideEndpointOptions(nil)

		// Dry mode needs Network Policy Updates, but the proxy wait group must
		// not be initialized, as there is no proxy ACKing the changes.
		if err, _ = e.updateNetworkPolicy(owner, nil); err != nil {
			return 0, compilationExecuted, err
		}

		if err = e.writeHeaderfile(nextDir, owner); err != nil {
			return 0, compilationExecuted, fmt.Errorf("Unable to write header file: %s", err)
		}

		log.WithField(logfields.EndpointID, e.ID).Debug("Skipping bpf updates due to dry mode")
		return e.nextPolicyRevision, compilationExecuted, nil
	}

	if e.PolicyMap == nil {
		e.PolicyMap, _, err = policymap.OpenMap(e.PolicyMapPathLocked())
		if err != nil {
			e.Unlock()
			return 0, compilationExecuted, err
		}
		// Clean up map contents
		e.getLogger().Debug("flushing old PolicyMap")
		err = e.PolicyMap.Flush()
		if err != nil {
			e.Unlock()
			return 0, compilationExecuted, err
		}

		// Also reset the in-memory state of the realized state as the
		// BPF map content is guaranteed to be empty right now.
		e.realizedMapState = make(PolicyMapState)
	}

	if e.bpfConfigMap == nil {
		e.bpfConfigMap, _, err = bpfconfig.OpenMapWithName(e.BPFConfigMapPath(), e.BPFConfigMapName())
		if err != nil {
			e.Unlock()
			return 0, compilationExecuted, err
		}
		// Also reset the in-memory state of the realized state as the
		// BPF map content is guaranteed to be empty right now.
		e.realizedBPFConfig = &bpfconfig.EndpointConfig{}
	}

	// Set up a context to wait for proxy completions.
	completionCtx, cancel := context.WithTimeout(context.Background(), EndpointGenerationTimeout)
	proxyWaitGroup := completion.NewWaitGroup(completionCtx)
	defer cancel()

	// Keep track of the side-effects of the regeneration that need to be
	// reverted in case of failure.
	// Also keep track of the regeneration finalization code that can't be
	// reverted, and execute it in case of regeneration success.
	var finalizeList revert.FinalizeList
	var revertStack revert.RevertStack
	defer func() {
		if reterr == nil {
			// Always execute the finalization code, even if the endpoint is
			// terminating, in order to properly release resources.
			e.UnconditionalLock()
			e.getLogger().Debug("Finalizing successful endpoint regeneration")
			finalizeList.Finalize()
			e.Unlock()
		} else {
			if err := e.LockAlive(); err != nil {
				e.getLogger().WithError(err).Debug("Skipping unnecessary restoring endpoint state")
				return
			}
			e.getLogger().Error("Restoring endpoint state after BPF regeneration failed")
			if err := revertStack.Revert(); err != nil {
				e.getLogger().WithError(err).Error("Restoring endpoint state failed")
			}
			e.getLogger().Error("Finished restoring endpoint state after BPF regeneration failed")
			e.Unlock()
		}
	}()

	// Only generate & populate policy map if a security identity is set up for
	// this endpoint.
	if e.SecurityIdentity != nil {
		stats.policyCalculation.Start()
		err = e.regeneratePolicy(owner)
		stats.policyCalculation.End(err == nil)
		if err != nil {
			e.Unlock()
			return 0, compilationExecuted, fmt.Errorf("unable to regenerate policy for '%s': %s", e.PolicyMap.String(), err)
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
			e.Unlock()
			return 0, compilationExecuted, fmt.Errorf("unable to regenerate policy because PolicyMap synchronization failed: %s", err)
		}

		// Synchronously update the BPF ConfigMap for this endpoint.
		// This is unlikely to fail, but will have the same
		// inconsistency issues as above if there is a failure. Long
		// term the solution to this is to templatize this map in the
		// ELF file, but there's no solution to this just yet.
		if err = e.bpfConfigMap.Update(e.desiredBPFConfig); err != nil {
			e.getLogger().WithError(err).Error("unable to update BPF config map")
			e.Unlock()
			return 0, compilationExecuted, err
		}

		revertStack.Push(func() error {
			return e.bpfConfigMap.Update(e.realizedBPFConfig)
		})

		// Configure the new network policy with the proxies.
		stats.proxyPolicyCalculation.Start()
		var networkPolicyRevertFunc revert.RevertFunc
		err, networkPolicyRevertFunc = e.updateNetworkPolicy(owner, proxyWaitGroup)
		stats.proxyPolicyCalculation.End(err == nil)
		if err != nil {
			e.Unlock()
			return 0, compilationExecuted, err
		}

		revertStack.Push(networkPolicyRevertFunc)
	}

	stats.proxyConfiguration.Start()
	var finalizeFunc revert.FinalizeFunc
	var revertFunc revert.RevertFunc
	// Walk the L4Policy to add new redirects and update the desired policy map
	// state to set the newly allocated proxy ports.
	var desiredRedirects map[string]bool
	if e.DesiredL4Policy != nil {
		desiredRedirects, err, finalizeFunc, revertFunc = e.addNewRedirects(owner, e.DesiredL4Policy, proxyWaitGroup)
		if err != nil {
			stats.proxyConfiguration.End(false)
			e.Unlock()
			return 0, compilationExecuted, err
		}
		finalizeList.Append(finalizeFunc)
		revertStack.Push(revertFunc)
	}
	// At this point, traffic is no longer redirected to the proxy for
	// now-obsolete redirects, since we synced the updated policy map above.
	// It's now safe to remove the redirects from the proxy's configuration.
	finalizeFunc, revertFunc = e.removeOldRedirects(owner, desiredRedirects, proxyWaitGroup)
	finalizeList.Append(finalizeFunc)
	revertStack.Push(revertFunc)
	stats.proxyConfiguration.End(true)

	stats.prepareBuild.Start()

	// Generate header file specific to this endpoint for use in compiling
	// BPF programs for this endpoint.
	if err = e.writeHeaderfile(nextDir, owner); err != nil {
		stats.prepareBuild.End(false)
		e.Unlock()
		return 0, compilationExecuted, fmt.Errorf("unable to write header file: %s", err)
	}

	// Avoid BPF program compilation and installation if the headerfile for the endpoint
	// or the node have not changed.
	bpfHeaderfilesHash, err := hashEndpointHeaderfiles(nextDir)
	var bpfHeaderfilesChanged bool
	if err != nil {
		e.getLogger().WithError(err).Warn("Unable to hash header file")
		bpfHeaderfilesHash = ""
		bpfHeaderfilesChanged = true
	} else {
		bpfHeaderfilesChanged = (bpfHeaderfilesHash != e.bpfHeaderfileHash)
		e.getLogger().WithField(logfields.BPFHeaderfileHash, bpfHeaderfilesHash).
			Debugf("BPF header file hashed (was: %q)", e.bpfHeaderfileHash)
	}

	// Cache endpoint information
	// TODO (ianvernon): why do we need to do this?
	var epInfoCache *epInfoCache
	if bpfHeaderfilesChanged {
		epInfoCache = e.createEpInfoCache(nextDir)
	} else {
		epInfoCache = e.createEpInfoCache(currentDir)
	}
	if epInfoCache == nil {
		stats.prepareBuild.End(false)
		e.Unlock()
		err = fmt.Errorf("Unable to cache endpoint information")
		return 0, compilationExecuted, err
	}

	// TODO: In Cilium v1.4 or later cycle, remove this.
	os.RemoveAll(e.IPv6EgressMapPathLocked())
	os.RemoveAll(e.IPv4EgressMapPathLocked())
	os.RemoveAll(e.IPv6IngressMapPathLocked())
	os.RemoveAll(e.IPv4IngressMapPathLocked())

	e.Unlock()

	// Wait for connection tracking cleaning to complete
	stats.waitingForCTClean.Start()
	<-ctCleaned
	stats.waitingForCTClean.End(true)

	e.getLogger().WithField("bpfHeaderfilesChanged", bpfHeaderfilesChanged).Debug("Preparing to compile BPF")

	stats.prepareBuild.End(true)
	if bpfHeaderfilesChanged || reloadDatapath {
		closeChan := loadinfo.LogPeriodicSystemLoad(log.WithFields(logrus.Fields{logfields.EndpointID: epID}).Debugf, time.Second)

		// Compile and install BPF programs for this endpoint
		ctx, cancel := context.WithTimeout(context.Background(), ExecTimeout)
		if bpfHeaderfilesChanged {
			stats.bpfCompilation.Start()
			err = loader.CompileAndLoad(ctx, epInfoCache)
			stats.bpfCompilation.End(err == nil)
			e.getLogger().WithError(err).
				WithField(logfields.BPFCompilationTime, stats.bpfCompilation.Total().String()).
				Info("Recompiled endpoint BPF program")
			compilationExecuted = true
		} else {
			err = loader.ReloadDatapath(ctx, epInfoCache)
			e.getLogger().WithError(err).Info("Reloaded endpoint BPF program")
		}
		cancel()
		close(closeChan)

		if err != nil {
			return epInfoCache.revision, compilationExecuted, err
		}
		e.bpfHeaderfileHash = bpfHeaderfilesHash
	} else {
		e.getLogger().WithField(logfields.BPFHeaderfileHash, bpfHeaderfilesHash).
			Debug("BPF header file unchanged, skipping BPF compilation and installation")
	}

	stats.proxyWaitForAck.Start()
	err = e.WaitForProxyCompletions(proxyWaitGroup)
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
	if err != nil {
		stats.mapSync.End(false)
		return 0, compilationExecuted, fmt.Errorf("unable to regenerate policy because PolicyMap synchronization failed: %s", err)
	}

	// The last operation hooks the endpoint into the endpoint table and exposes it
	err = lxcmap.WriteEndpoint(epInfoCache)
	if err != nil {
		log.WithField(logfields.EndpointID, e.ID).WithError(err).Error("Exposing new bpf failed")
	}
	stats.mapSync.End(true)

	return epInfoCache.revision, compilationExecuted, err
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
	}
	for name, path := range maps {
		if err := os.RemoveAll(path); err != nil {
			errors = append(errors, fmt.Errorf("unable to remove %s map file %s: %s", name, path, err))
		}
	}

	if e.ConntrackLocalLocked() {
		// Remove local connection tracking maps
		for _, m := range ctmap.LocalMaps(e, !option.Config.IPv4Disabled, true) {
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
	if err := e.RemoveFromGlobalPolicyMap(); err != nil {
		errors = append(errors, fmt.Errorf("unable to remove endpoint from global policy map: %s", err))
	}

	return errors
}
