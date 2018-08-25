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
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/loadinfo"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/spanstat"
	"github.com/cilium/cilium/pkg/version"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	// ExecTimeout is the execution timeout to use in join_ep.sh executions
	ExecTimeout = 300 * time.Second

	// EndpointGenerationTimeout specifies timeout for proxy completion context
	EndpointGenerationTimeout = 55 * time.Second
)

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

	// If policy has not been derived or calculated yet, all packets must
	// be dropped until the policy of the endpoint has been determined,
	// except when it is known that the current policy will not drop anything,
	// which is true when:
	// - policy enforcement mode is "never"
	// - policy enforcement mode is "default" and no policies are loaded
	if !e.PolicyCalculated &&
		!(owner.PolicyEnforcement() == option.NeverEnforce) &&
		!(owner.PolicyEnforcement() == option.DefaultEnforcement && owner.GetPolicyRepository().Empty()) {
		fw.WriteString("#define DROP_ALL\n")
	}

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
	if e.Options.IsEnabled(option.ConntrackLocal) {
		fmt.Fprintf(fw, "#define CT_MAP_SIZE %s\n", strconv.Itoa(ctmap.MapNumEntriesLocal))
		fmt.Fprintf(fw, "#define CT_MAP6 %s\n", ctmap.MapName6+strconv.Itoa(int(e.ID)))
		fmt.Fprintf(fw, "#define CT_MAP4 %s\n", ctmap.MapName4+strconv.Itoa(int(e.ID)))
	} else {
		fmt.Fprintf(fw, "#define CT_MAP_SIZE %s\n", strconv.Itoa(ctmap.MapNumEntriesGlobal))
		fmt.Fprintf(fw, "#define CT_MAP6 %s\n", ctmap.MapName6Global)
		fmt.Fprintf(fw, "#define CT_MAP4 %s\n", ctmap.MapName4Global)
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

func (e *Endpoint) runInit(libdir, rundir, epdir, ifName, debug string) error {
	args := []string{libdir, rundir, epdir, ifName, debug, e.StringID()}
	prog := filepath.Join(libdir, "join_ep.sh")

	scopedLog := e.getLogger()

	ctx, cancel := context.WithTimeout(context.Background(), ExecTimeout)
	defer cancel()

	joinEpCmd := exec.CommandContext(ctx, prog, args...)
	joinEpCmd.Env = bpf.Environment()
	out, err := joinEpCmd.CombinedOutput()

	cmd := fmt.Sprintf("%s %s", prog, strings.Join(args, " "))
	scopedLog = scopedLog.WithField("cmd", cmd)
	if ctx.Err() == context.DeadlineExceeded {
		scopedLog.Error("RunInit: Command execution failed: Timeout")
		return ctx.Err()
	}
	if err != nil {
		scopedLog.WithError(err).Warn("RunInit: Command execution failed")
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			log.Warn(scanner.Text())
		}
		return fmt.Errorf("error: %q command output: %q", err, out)
	}

	return nil
}

// epInfoCache describes the set of lxcmap entries necessary to describe an Endpoint
// in the BPF maps. It is generated while holding the Endpoint lock, then used
// after releasing that lock to push the entries into the datapath.
// Functions below implement the EndpointFrontend interface with this cached information.
type epInfoCache struct {
	keys     []*lxcmap.EndpointKey
	value    *lxcmap.EndpointInfo
	ifName   string
	revision uint64
}

// Must be called when endpoint is still locked.
func (e *Endpoint) createEpInfoCache() *epInfoCache {
	ep := &epInfoCache{ifName: e.IfName, revision: e.nextPolicyRevision}
	var err error
	ep.keys = e.GetBPFKeys()
	ep.value, err = e.GetBPFValue()
	if err != nil {
		log.WithField(logfields.EndpointID, e.ID).WithError(err).Error("getBPFValue failed")
		return nil
	}
	return ep
}

// GetBPFKeys returns all keys which should represent this endpoint in the BPF
// endpoints map
func (ep *epInfoCache) GetBPFKeys() []*lxcmap.EndpointKey {
	return ep.keys
}

// GetBPFValue returns the value which should represent this endpoint in the
// BPF endpoints map
// Must only be called if init() succeeded.
func (ep *epInfoCache) GetBPFValue() (*lxcmap.EndpointInfo, error) {
	return ep.value, nil
}

// addNewRedirectsFromMap must be called while holding the endpoint lock for
// writing. On success, returns nil; otherwise, returns an error  indicating the
// problem that occurred while adding an l7 redirect for the specified policy.
// Must be called with endpoint.Mutex held.
func (e *Endpoint) addNewRedirectsFromMap(owner Owner, m policy.L4PolicyMap, desiredRedirects map[string]bool, proxyWaitGroup *completion.WaitGroup) error {
	if owner.DryModeEnabled() {
		return nil
	}

	for _, l4 := range m {
		if l4.IsRedirect() {
			var redirectPort uint16
			var err error
			// Only create a redirect if the proxy is NOT running in a sidecar
			// container. If running in a sidecar container, just allow traffic
			// to the port at L4 by setting the proxy port to 0.
			if !e.hasSidecarProxy || l4.L7Parser != policy.ParserTypeHTTP {
				redirectPort, err = owner.UpdateProxyRedirect(e, &l4, proxyWaitGroup)
				if err != nil {
					return err
				}

				proxyID := e.ProxyID(&l4)
				if e.realizedRedirects == nil {
					e.realizedRedirects = make(map[string]uint16)
				}
				e.realizedRedirects[proxyID] = redirectPort
				desiredRedirects[proxyID] = true

				// Update the endpoint API model to report that Cilium manages a
				// redirect for that port.
				e.proxyStatisticsMutex.Lock()
				proxyStats := e.getProxyStatisticsLocked(string(l4.L7Parser), uint16(l4.Port), l4.Ingress)
				proxyStats.AllocatedProxyPort = int64(redirectPort)
				e.proxyStatisticsMutex.Unlock()
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
				e.desiredMapState[keyFromFilter] = PolicyMapStateEntry{ProxyPort: redirectPort}
			}
		}
	}
	return nil
}

// addNewRedirects must be called while holding the endpoint lock for writing.
// On success, returns nil; otherwise, returns an error indicating the problem
// that occurred while adding an l7 redirect for the specified policy.
// The returned map contains the exact set of IDs of proxy redirects that is
// required to implement the given L4 policy.
// Must be called with endpoint.Mutex held.
func (e *Endpoint) addNewRedirects(owner Owner, m *policy.L4Policy, proxyWaitGroup *completion.WaitGroup) (desiredRedirects map[string]bool, err error) {
	desiredRedirects = make(map[string]bool)
	if err = e.addNewRedirectsFromMap(owner, m.Ingress, desiredRedirects, proxyWaitGroup); err != nil {
		return desiredRedirects, fmt.Errorf("Unable to allocate ingress redirects: %s", err)
	}
	if err = e.addNewRedirectsFromMap(owner, m.Egress, desiredRedirects, proxyWaitGroup); err != nil {
		return desiredRedirects, fmt.Errorf("Unable to allocate egress redirects: %s", err)
	}
	return desiredRedirects, nil
}

// Must be called with endpoint.Mutex held.
func (e *Endpoint) removeOldRedirects(owner Owner, desiredRedirects map[string]bool, proxyWaitGroup *completion.WaitGroup) {
	if owner.DryModeEnabled() {
		return
	}

	for id, redirectPort := range e.realizedRedirects {
		// Remove only the redirects that are not required.
		if desiredRedirects[id] {
			continue
		}
		if err := owner.RemoveProxyRedirect(e, id, proxyWaitGroup); err != nil {
			e.getLogger().WithError(err).WithField(logfields.L4PolicyID, id).Warn("Error while removing proxy redirect")
		} else {
			delete(e.realizedRedirects, id)

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
					stats.AllocatedProxyPort = 0
					break
				}
			}
			e.proxyStatisticsMutex.Unlock()
		}
	}
}

type regenerationStatistics struct {
	totalTime              spanstat.SpanStat
	waitingForLock         spanstat.SpanStat
	waitingForCTClean      spanstat.SpanStat
	policyCalculation      spanstat.SpanStat
	proxyConfiguration     spanstat.SpanStat
	proxyPolicyCalculation spanstat.SpanStat
	proxyWaitForAck        spanstat.SpanStat
	bpfCompilation         spanstat.SpanStat
	mapSync                spanstat.SpanStat
	prepareBuild           spanstat.SpanStat
}

// regeneratePolicyAndBPF calculates policy, updates all BPF maps and
// recompiles the BPF program if needed.  Returns the implemented policy
// revision and a boolean indicating whether a BPF compilation was required.
//
// Must be called with endpoint.Mutex NOT held
func (e *Endpoint) regeneratePolicyAndBPF(owner Owner, epdir, reason string, stats *regenerationStatistics) (revnum uint64, compiled bool, reterr error) {
	var (
		err                 error
		compilationExecuted bool
	)

	stats.waitingForLock.Start()

	// Make sure that owner is not compiling base programs while we are
	// regenerating an endpoint.
	owner.GetCompilationLock().RLock()
	defer owner.GetCompilationLock().RUnlock()

	ctCleaned := make(chan struct{})

	if err = e.LockAlive(); err != nil {
		return 0, compilationExecuted, err
	}
	stats.waitingForLock.End()

	epID := e.StringID()

	// In the first ever regeneration of the endpoint, the conntrack table
	// is cleaned from the new endpoint IPs as it is guaranteed that any
	// pre-existing connections using that IP are now invalid.
	if !e.ctCleaned {
		go func() {
			e.scrubIPsInConntrackTable()
			close(ctCleaned)
		}()
	} else {
		close(ctCleaned)
	}

	// If dry mode is enabled, no further changes to BPF maps are performed
	if owner.DryModeEnabled() {
		defer e.Unlock()

		// Regenerate policy and apply any options resulting in the
		// policy change.
		// Note that PolicyMap is not initialized!
		if _, err = e.regeneratePolicy(owner, nil); err != nil {
			return 0, compilationExecuted, fmt.Errorf("Unable to regenerate policy: %s", err)
		}

		// Dry mode needs Network Policy Updates, but the proxy wait group must
		// not be initialized, as there is no proxy ACKing the changes.
		if err = e.updateNetworkPolicy(owner, nil); err != nil {
			return 0, compilationExecuted, err
		}

		if err = e.writeHeaderfile(epdir, owner); err != nil {
			return 0, compilationExecuted, fmt.Errorf("Unable to write header file: %s", err)
		}

		log.WithField(logfields.EndpointID, e.ID).Debug("Skipping bpf updates due to dry mode")
		return e.nextPolicyRevision, compilationExecuted, nil
	}

	// Anything below this point must be reverted upon failure as we are
	// changing live BPF maps
	createdPolicyMap := false

	defer func() {
		if reterr != nil {
			e.getLogger().WithError(err).Error("destroying BPF maps due to" +
				" errors during regeneration")
			if createdPolicyMap {
				e.UnconditionalLock()
				e.getLogger().Debug("removing endpoint PolicyMap")
				os.RemoveAll(e.PolicyMapPathLocked())
				e.PolicyMap = nil
				e.Unlock()
			}
		}
	}()

	if e.PolicyMap == nil {
		e.PolicyMap, createdPolicyMap, err = policymap.OpenMap(e.PolicyMapPathLocked())
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
	}

	// Set up a context to wait for proxy completions.
	completionCtx, cancel := context.WithTimeout(context.Background(), EndpointGenerationTimeout)
	proxyWaitGroup := completion.NewWaitGroup(completionCtx)
	defer cancel()

	// Only generate & populate policy map if a security identity is set up for
	// this endpoint.
	if e.SecurityIdentity != nil {

		// Regenerate policy and apply any options resulting in the
		// policy change.
		// This also populates e.PolicyMap.
		stats.policyCalculation.Start()
		_, err = e.regeneratePolicy(owner, nil)
		if err != nil {
			e.Unlock()
			return 0, compilationExecuted, fmt.Errorf("unable to regenerate policy for '%s': %s", e.PolicyMap.String(), err)
		}
		stats.policyCalculation.End()

		// Synchronously try to update PolicyMap for this endpoint. If any
		// part of updating the PolicyMap fails, bail out and do not generate
		// BPF. Unfortunately, this means that the map will be in an inconsistent
		// state with the current program (if it exists) for this endpoint.
		// GH-3897 would fix this by creating a new map to do an atomic swap
		// with the old one.
		stats.mapSync.Start()
		err := e.syncPolicyMap()
		if err != nil {
			e.Unlock()
			return 0, compilationExecuted, fmt.Errorf("unable to regenerate policy because PolicyMap synchronization failed: %s", err)
		}
		stats.mapSync.End()

		// Configure the new network policy with the proxies.
		stats.proxyPolicyCalculation.Start()
		if err = e.updateNetworkPolicy(owner, proxyWaitGroup); err != nil {
			e.Unlock()
			return 0, compilationExecuted, err
		}
		stats.proxyPolicyCalculation.End()
	}

	stats.proxyConfiguration.Start()

	// Walk the L4Policy to add new redirects and update the desired policy map
	// state to set the newly allocated proxy ports.
	var desiredRedirects map[string]bool
	if e.DesiredL4Policy != nil {
		desiredRedirects, err = e.addNewRedirects(owner, e.DesiredL4Policy, proxyWaitGroup)
		if err != nil {
			e.Unlock()
			return 0, compilationExecuted, err
		}
	}
	// At this point, traffic is no longer redirected to the proxy for
	// now-obsolete redirects, since we synced the updated policy map above.
	// It's now safe to remove the redirects from the proxy's configuration.
	e.removeOldRedirects(owner, desiredRedirects, proxyWaitGroup)
	stats.proxyConfiguration.End()

	stats.prepareBuild.Start()

	// Generate header file specific to this endpoint for use in compiling
	// BPF programs for this endpoint.
	if err = e.writeHeaderfile(epdir, owner); err != nil {
		e.Unlock()
		return 0, compilationExecuted, fmt.Errorf("unable to write header file: %s", err)
	}

	// Avoid BPF program compilation and installation if the headerfile for the endpoint
	// or the node have not changed.
	bpfHeaderfilesHash, err := hashEndpointHeaderfiles(epdir)
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
	epInfoCache := e.createEpInfoCache()
	if epInfoCache == nil {
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

	e.getLogger().WithField("bpfHeaderfilesChanged", bpfHeaderfilesChanged).Debug("Preparing to compile BPF")
	libdir := owner.GetBpfDir()
	rundir := owner.GetStateDir()
	debug := strconv.FormatBool(viper.GetBool(option.BPFCompileDebugName))

	stats.prepareBuild.End()

	if bpfHeaderfilesChanged {
		closeChan := loadinfo.LogPeriodicSystemLoad(log.WithFields(logrus.Fields{logfields.EndpointID: epID}).Debugf, time.Second)

		stats.bpfCompilation.Start()
		// Compile and install BPF programs for this endpoint
		err = e.runInit(libdir, rundir, epdir, epInfoCache.ifName, debug)
		stats.bpfCompilation.End()
		close(closeChan)

		e.getLogger().WithError(err).
			WithField(logfields.BPFCompilationTime, stats.bpfCompilation.Total().String()).
			Info("Recompiled endpoint BPF program")

		if err != nil {
			return epInfoCache.revision, compilationExecuted, err
		}
		compilationExecuted = true
		e.bpfHeaderfileHash = bpfHeaderfilesHash
	} else {
		e.UnconditionalRLock()
		e.getLogger().WithField(logfields.BPFHeaderfileHash, bpfHeaderfilesHash).
			Debug("BPF header file unchanged, skipping BPF compilation and installation")
		e.RUnlock()
	}

	stats.proxyWaitForAck.Start()
	err = e.WaitForProxyCompletions(proxyWaitGroup)
	if err != nil {
		return 0, compilationExecuted, fmt.Errorf("Error while configuring proxy redirects: %s", err)
	}
	stats.proxyWaitForAck.End()

	// Wait for connection tracking cleaning to be complete
	stats.waitingForCTClean.Start()
	<-ctCleaned
	stats.waitingForCTClean.End()

	stats.waitingForLock.Start()
	if err = e.LockAlive(); err != nil {
		return 0, compilationExecuted, err
	}
	stats.waitingForLock.End()
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
		return 0, compilationExecuted, fmt.Errorf("unable to regenerate policy because PolicyMap synchronization failed: %s", err)
	}

	// The last operation hooks the endpoint into the endpoint table and exposes it
	err = lxcmap.WriteEndpoint(epInfoCache)
	if err != nil {
		log.WithField(logfields.EndpointID, e.ID).WithError(err).Error("Exposing new bpf failed")
	}
	stats.mapSync.End()

	return epInfoCache.revision, compilationExecuted, err
}
