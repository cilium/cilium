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
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/cidrmap"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/cilium/pkg/version"

	"github.com/spf13/viper"
)

const (
	// ExecTimeout is the execution timeout to use in join_ep.sh executions
	ExecTimeout = 300 * time.Second
)

// lookupRedirectPortBE returns the redirect L4 proxy port for the given L4
// filter, in big-endian (network) byte order. Returns 0 if not found or the
// filter doesn't require a redirect.
// Must be called with Endpoint.Mutex held.
func (e *Endpoint) lookupRedirectPortBE(l4Filter *policy.L4Filter) uint16 {
	if !l4Filter.IsRedirect() {
		return 0
	}
	proxyID := e.ProxyID(l4Filter)
	return byteorder.HostToNetwork(e.realizedRedirects[proxyID]).(uint16)
}

// filterAccumulator accumulates proxyport / L4 allow configurations during
// e.writeL4Map() iteration. One will be defined for L4-only filters,
// and one for L3-dependent L4 filters.
type filterAccumulator struct {
	config string
	array  string
	index  int
}

func (fa *filterAccumulator) add(dport, redirect uint16, protoNum uint8) {
	entry := fmt.Sprintf("%d,%d,%d,%d", fa.index, dport, redirect, protoNum)
	if fa.array != "" {
		fa.array = fa.array + "," + entry
	} else {
		fa.array = entry
	}
	fa.index++
}

func (fa *filterAccumulator) writeL4Map(fw *bufio.Writer) {
	if fa.array == "" {
		fmt.Fprintf(fw, "#undef %s\n", fa.config)
	} else {
		fmt.Fprintf(fw, "#define %s %s, (), 0\n", fa.config, fa.array)
		fmt.Fprintf(fw, "#define NR_%s %d\n", fa.config, fa.index)
	}
}

func (e *Endpoint) writeL4Map(fw *bufio.Writer, m policy.L4PolicyMap, configL4, configL3L4 string) error {
	cidrl4cfg := &filterAccumulator{config: configL4}
	l3l4cfg := &filterAccumulator{config: configL3L4}

	for _, l4 := range m {
		// Represents struct l4_allow in bpf/lib/l4.h
		protoNum, err := u8proto.ParseProtocol(string(l4.Protocol))
		if err != nil {
			return fmt.Errorf("invalid protocol %s", l4.Protocol)
		}

		dport := byteorder.HostToNetwork(uint16(l4.Port)).(uint16)
		redirect := e.lookupRedirectPortBE(&l4)
		if l4.Endpoints == nil {
			cidrl4cfg.add(dport, redirect, uint8(protoNum))
		}
		l3l4cfg.add(dport, redirect, uint8(protoNum))
	}

	cidrl4cfg.writeL4Map(fw)
	l3l4cfg.writeL4Map(fw)

	return nil
}

func (e *Endpoint) writeL4Policy(fw *bufio.Writer) error {
	if e.DesiredL4Policy == nil {
		return nil
	}

	// Out of caution, make a local copy of the DesiredL4Policy in case
	// enpdoint's DesiredL4Policy gets updated elsewhere.
	l4policy := e.DesiredL4Policy

	fmt.Fprintf(fw, "#define HAVE_L4_POLICY\n")

	if err := e.writeL4Map(fw, l4policy.Ingress, "CFG_CIDRL4_INGRESS", "CFG_L3L4_INGRESS"); err != nil {
		return err
	}

	return e.writeL4Map(fw, l4policy.Egress, "CFG_CIDRL4_EGRESS", "CFG_L3L4_EGRESS")
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
		e.LogStatus(BPF, Warning, fmt.Sprintf("Unable to create a base64: %s", err))
	}

	if e.DockerID == "" {
		fmt.Fprintf(fw, " * Docker Network ID: %s\n", e.DockerNetworkID)
		fmt.Fprintf(fw, " * Docker Endpoint ID: %s\n", e.DockerEndpointID)
	} else {
		fmt.Fprintf(fw, " * Docker Container ID: %s\n", e.DockerID)
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
	if e.L3Policy != nil {
		fmt.Fprintf(fw, "#define LPM_MAP_VALUE_SIZE %s\n", strconv.Itoa(cidrmap.LPM_MAP_VALUE_SIZE))
		if len(e.L3Policy.Ingress.IPv6PrefixCount) > 0 {
			fmt.Fprintf(fw, "#define CIDR6_INGRESS_MAP %s\n", path.Base(e.IPv6IngressMapPathLocked()))
		}
		if len(e.L3Policy.Ingress.IPv4PrefixCount) > 0 {
			fmt.Fprintf(fw, "#define CIDR4_INGRESS_MAP %s\n", path.Base(e.IPv4IngressMapPathLocked()))
		}
	}
	fmt.Fprintf(fw, "#define CALLS_MAP %s\n", path.Base(e.CallsMapPathLocked()))
	if e.Opts.IsEnabled(option.ConntrackLocal) {
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
	fw.WriteString(e.Opts.GetFmtList())

	if err := e.writeL4Policy(fw); err != nil {
		return err
	}

	if e.L3Policy != nil {
		ipv6Ingress, ipv4Ingress := e.L3Policy.Ingress.ToBPFData()

		if len(ipv6Ingress) > 0 {
			fw.WriteString("#define CIDR6_INGRESS_PREFIXES ")
			for _, m := range ipv6Ingress {
				fmt.Fprintf(fw, "%d,", m)
			}
			fw.WriteString("\n")
		}
		if len(ipv4Ingress) > 0 {
			fw.WriteString("#define CIDR4_INGRESS_PREFIXES ")
			for _, m := range ipv4Ingress {
				fmt.Fprintf(fw, "%d,", m)
			}
			fw.WriteString("\n")
		}
	}

	// IPCache only supports hosts at the moment, only set host prefix
	ipcachePrefixes6, ipcachePrefixes4 := ipcache.IPIdentityCache.ToBPFData()
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

	return fw.Flush()
}

// hashHeaderfile returns the MD5 hash of the BPF headerfile with the given prefix.
// This ignores all lines that don't start with "#", incl. all comments, since
// they have no effect on the BPF compilation.
func hashHeaderfile(prefix string) (string, error) {
	headerPath := filepath.Join(prefix, common.CHeaderFileName)
	file, err := os.Open(headerPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hashWriter := md5.New()
	reader := bufio.NewReader(file)
	firstFragmentOfLine := true
	lineToHash := false
	for {
		fragment, isPrefix, err := reader.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err
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

	hash := hashWriter.Sum(nil)
	return hex.EncodeToString(hash[:]), nil
}

func (e *Endpoint) runInit(libdir, rundir, epdir, ifName, debug string) error {
	args := []string{libdir, rundir, epdir, ifName, debug, e.StringID()}
	prog := filepath.Join(libdir, "join_ep.sh")

	e.Mutex.RLock()
	scopedLog := e.getLogger() // must be called with e.Mutex held
	e.Mutex.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), ExecTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, prog, args...).CombinedOutput()

	cmd := fmt.Sprintf("%s %s", prog, strings.Join(args, " "))
	scopedLog = scopedLog.WithField("cmd", cmd)
	if ctx.Err() == context.DeadlineExceeded {
		scopedLog.Error("Command execution failed: Timeout")
		return ctx.Err()
	}
	if err != nil {
		scopedLog.WithError(err).Warn("Command execution failed")
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

// addNewRedirectsFromMap must be called while holding the endpoint and consumable
// locks for writing. On success, returns nil; otherwise, returns an error
// indicating the problem that occurred while adding an l7 redirect for the
// specified policy.
// Must be called with endpoint.Mutex held.
func (e *Endpoint) addNewRedirectsFromMap(owner Owner, m policy.L4PolicyMap, desiredRedirects map[string]bool) error {
	if owner.DryModeEnabled() {
		return nil
	}

	for _, l4 := range m {
		if l4.IsRedirect() {
			// Ignore the redirect if the proxy is running in a sidecar container.
			if l4.L7Parser == policy.ParserTypeHTTP && viper.GetBool("sidecar-http-proxy") {
				continue
			}

			redirectPort, err := owner.UpdateProxyRedirect(e, &l4)
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
	}
	return nil
}

// addNewRedirects must be called while holding the endpoint and consumable
// locks for writing. On success, returns nil; otherwise, returns an error
// indicating the problem that occurred while adding an l7 redirect for the
// specified policy.
// The returned map contains the exact set of IDs of proxy redirects that is
// required to implement the given L4 policy.
// Must be called with endpoint.Mutex held.
func (e *Endpoint) addNewRedirects(owner Owner, m *policy.L4Policy) (desiredRedirects map[string]bool, err error) {
	desiredRedirects = make(map[string]bool)
	if err = e.addNewRedirectsFromMap(owner, m.Ingress, desiredRedirects); err != nil {
		return desiredRedirects, fmt.Errorf("Unable to allocate ingress redirects: %s", err)
	}
	if err = e.addNewRedirectsFromMap(owner, m.Egress, desiredRedirects); err != nil {
		return desiredRedirects, fmt.Errorf("Unable to allocate egress redirects: %s", err)
	}
	return desiredRedirects, nil
}

// Must be called with endpoint.Mutex held.
func (e *Endpoint) removeOldRedirects(owner Owner, desiredRedirects map[string]bool) {
	if owner.DryModeEnabled() {
		return
	}

	for id, redirectPort := range e.realizedRedirects {
		// Remove only the redirects that are not required.
		if desiredRedirects[id] {
			continue
		}
		if err := owner.RemoveProxyRedirect(e, id); err != nil {
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

// regenerateBPF rewrites all headers and updates all BPF maps to reflect the
// specified endpoint.
// Must be called with endpoint.Mutex not held and endpoint.BuildMutex held.
func (e *Endpoint) regenerateBPF(owner Owner, epdir, reason string) (uint64, error) {
	var err error

	// Make sure that owner is not compiling base programs while we are
	// regenerating an endpoint.
	owner.GetCompilationLock().RLock()
	defer owner.GetCompilationLock().RUnlock()

	buildStart := time.Now()

	e.Mutex.Lock()

	e.getLogger().WithField(logfields.StartTime, time.Now()).Info("Regenerating BPF program")
	defer func() {
		e.Mutex.RLock()
		e.getLogger().WithField(logfields.BuildDuration, time.Since(buildStart).String()).
			Info("Regeneration of BPF program has completed")
		e.Mutex.RUnlock()
	}()

	// If endpoint was marked as disconnected then
	// it won't be regenerated.
	// When building the initial drop policy in waiting-for-identity state
	// the state remains unchanged
	if e.GetStateLocked() != StateWaitingForIdentity &&
		!e.BuilderSetStateLocked(StateRegenerating, "Regenerating Endpoint BPF: "+reason) {

		e.getLogger().WithField(logfields.EndpointState, e.state).Debug("Skipping build due to invalid state")
		e.Mutex.Unlock()
		return 0, fmt.Errorf("Skipping build due to invalid state: %s", e.state)
	}

	// If dry mode is enabled, no further changes to BPF maps are performed
	if owner.DryModeEnabled() {
		defer e.Mutex.Unlock()

		// Regenerate policy and apply any options resulting in the
		// policy change.
		// Note that PolicyMap is not initialized!
		if _, err = e.regeneratePolicy(owner, nil); err != nil {
			return 0, fmt.Errorf("Unable to regenerate policy: %s", err)
		}

		// Dry mode needs Network Policy Updates, but e.ProxyWaitGroup must not
		// be initialized, as there is no proxy ACKing the changes.
		if err = e.updateNetworkPolicy(owner); err != nil {
			return 0, err
		}

		if err = e.writeHeaderfile(epdir, owner); err != nil {
			return 0, fmt.Errorf("Unable to write header file: %s", err)
		}

		log.WithField(logfields.EndpointID, e.ID).Debug("Skipping bpf updates due to dry mode")
		return e.nextPolicyRevision, nil
	}

	completionCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	e.ProxyWaitGroup = completion.NewWaitGroup(completionCtx)
	defer func() {
		cancel()
		e.ProxyWaitGroup = nil
	}()

	// The set of IDs of proxy redirects that are required to implement the
	// policy.
	var desiredRedirects map[string]bool

	// Anything below this point must be reverted upon failure as we are
	// changing live BPF maps
	createdPolicyMap := false
	createdIPv6IngressMap := false
	createdIPv6EgressMap := false
	createdIPv4IngressMap := false
	createdIPv4EgressMap := false

	defer func() {
		if err != nil {
			e.Mutex.Lock()
			if createdPolicyMap {
				os.RemoveAll(e.PolicyMapPathLocked())
				e.PolicyMap = nil
			}

			if createdIPv6IngressMap {
				e.L3Maps.DestroyBpfMap(IPv6Ingress, e.IPv6IngressMapPathLocked())
			}
			if createdIPv6EgressMap {
				e.L3Maps.DestroyBpfMap(IPv6Egress, e.IPv6EgressMapPathLocked())
			}
			if createdIPv4IngressMap {
				e.L3Maps.DestroyBpfMap(IPv4Ingress, e.IPv4IngressMapPathLocked())
			}
			if createdIPv4EgressMap {
				e.L3Maps.DestroyBpfMap(IPv4Egress, e.IPv4EgressMapPathLocked())
			}
			e.Mutex.Unlock()
		}
	}()

	// Create the policymap on the first pass
	if e.PolicyMap == nil {
		e.PolicyMap, createdPolicyMap, err = policymap.OpenMap(e.PolicyMapPathLocked())
		if err != nil {
			e.Mutex.Unlock()
			return 0, err
		}
		// Clean up map contents
		log.Debugf("Flushing old policies map")
		err = e.PolicyMap.Flush()
		if err != nil {
			e.Mutex.Unlock()
			return 0, err
		}
	}

	// Only generate & populate policy map if a security identity is set up for
	// this endpoint.
	if e.SecurityIdentity != nil {

		// Regenerate policy and apply any options resulting in the
		// policy change.
		// This also populates e.PolicyMap.
		_, err = e.regeneratePolicy(owner, nil)
		if err != nil {
			e.Mutex.Unlock()
			return 0, fmt.Errorf("unable to regenerate policy for '%s': %s", e.PolicyMap.String(), err)
		}

		// Synchronously try to update PolicyMap for this endpoint. If any
		// part of updating the PolicyMap fails, bail out and do not generate
		// BPF. Unfortunately, this means that the map will be in an inconsistent
		// state with the current program (if it exists) for this endpoint.
		// GH-3897 would fix this by creating a new map to do an atomic swap
		// with the old one.
		err := e.syncPolicyMap()
		if err != nil {
			e.Mutex.Unlock()
			return 0, fmt.Errorf("unable to regenerate policy because PolicyMap synchronization failed: %s", err)
		}

		// Walk the L4Policy for ports that require
		// an L7 redirect and add them to the endpoint.
		if e.DesiredL4Policy != nil {
			desiredRedirects, err = e.addNewRedirects(owner, e.DesiredL4Policy)
			if err != nil {
				e.Mutex.Unlock()
				return 0, err
			}
		}
		// Update policies after adding redirects, otherwise we will not wait for
		// acks for the first policy upates for the first added redirects.
		if err = e.updateNetworkPolicy(owner); err != nil {
			e.Mutex.Unlock()
			return 0, err
		}
	}

	// Generate header file specific to this endpoint for use in compiling
	// BPF programs for this endpoint.
	if err = e.writeHeaderfile(epdir, owner); err != nil {
		e.Mutex.Unlock()
		return 0, fmt.Errorf("unable to write header file: %s", err)
	}

	// Avoid BPF program compilation and installation if the headerfile hasn't changed.
	bpfHeaderfileHash, err := hashHeaderfile(epdir)
	var bpfHeaderfileChanged bool
	if err != nil {
		e.getLogger().WithError(err).Warn("Unable to hash header file")
		bpfHeaderfileHash = ""
		bpfHeaderfileChanged = true
	} else {
		bpfHeaderfileChanged = (bpfHeaderfileHash != e.bpfHeaderfileHash)
		e.getLogger().WithField(logfields.BPFHeaderfileHash, bpfHeaderfileHash).
			Debugf("BPF header file hashed (was: %q)", e.bpfHeaderfileHash)
	}

	// Cache endpoint information
	// TODO (ianvernon): why do we need to do this?
	epInfoCache := e.createEpInfoCache()
	if epInfoCache == nil {
		e.Mutex.Unlock()
		err = fmt.Errorf("Unable to cache endpoint information")
		return 0, err
	}

	// Populate maps used for CIDR-based policy. If the maps would be empty,
	// just delete the maps.
	if e.L3Policy != nil {
		if len(e.L3Policy.Ingress.IPv6PrefixCount) > 0 &&
			e.L3Maps.ResetBpfMap(IPv6Ingress, e.IPv6IngressMapPathLocked()) == nil {
			createdIPv6IngressMap = true
			e.L3Policy.Ingress.PopulateBPF(e.L3Maps[IPv6Ingress])
		} else {
			e.L3Maps.DestroyBpfMap(IPv6Ingress, e.IPv6IngressMapPathLocked())
		}
		if len(e.L3Policy.Ingress.IPv4PrefixCount) > 0 &&
			e.L3Maps.ResetBpfMap(IPv4Ingress, e.IPv4IngressMapPathLocked()) == nil {
			createdIPv4IngressMap = true
			e.L3Policy.Ingress.PopulateBPF(e.L3Maps[IPv4Ingress])
		} else {
			e.L3Maps.DestroyBpfMap(IPv4Ingress, e.IPv4IngressMapPathLocked())
		}
		// TODO: In Cilium v1.4 or later cycle, remove this.
		e.L3Maps.DestroyBpfMap(IPv6Egress, e.IPv6EgressMapPathLocked())
		e.L3Maps.DestroyBpfMap(IPv4Egress, e.IPv4EgressMapPathLocked())
	}

	e.Mutex.Unlock()

	libdir := owner.GetBpfDir()
	rundir := owner.GetStateDir()
	debug := strconv.FormatBool(owner.DebugEnabled())

	// To avoid traffic loss, wait for the proxy to be ready to accept traffic
	// on new redirect ports, before we generate the policy that will redirect
	// traffic to those ports.
	err = e.WaitForProxyCompletions()
	if err != nil {
		return 0, fmt.Errorf("Error while configuring proxy redirects: %s", err)
	}

	if bpfHeaderfileChanged {
		// Compile and install BPF programs for this endpoint
		err = e.runInit(libdir, rundir, epdir, epInfoCache.ifName, debug)
		if err != nil {
			return epInfoCache.revision, err
		}
		e.bpfHeaderfileHash = bpfHeaderfileHash
	} else {
		e.Mutex.RLock()
		e.getLogger().WithField(logfields.BPFHeaderfileHash, bpfHeaderfileHash).
			Debug("BPF header file unchanged, skipping BPF compilation and installation")
		e.Mutex.RUnlock()
	}

	// To avoid traffic loss, wait for the policy to be pushed into BPF before
	// deleting obsolete redirects, to make sure no packets are redirected to
	// those ports.
	completionCtx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	e.ProxyWaitGroup = completion.NewWaitGroup(completionCtx)
	defer cancel()
	e.Mutex.Lock()
	e.removeOldRedirects(owner, desiredRedirects)
	e.Mutex.Unlock()
	err = e.WaitForProxyCompletions()
	if err != nil {
		return 0, fmt.Errorf("Error while deleting obsolete proxy redirects: %s", err)
	}

	// The last operation hooks the endpoint into the endpoint table and exposes it
	err = lxcmap.WriteEndpoint(epInfoCache)
	if err != nil {
		log.WithField(logfields.EndpointID, e.ID).WithError(err).Error("Exposing new bpf failed")
	}

	return epInfoCache.revision, err
}
