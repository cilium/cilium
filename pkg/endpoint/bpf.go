// Copyright 2016-2017 Authors of Cilium
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
	"fmt"
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
	"github.com/cilium/cilium/pkg/geneve"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/cidrmap"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
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

// ParseL4Filter parses a L4Filter and returns a L4RuleContext and a
// L7RuleContext with L4Installed set to false.
// Must be called with Endpoint.Mutex held.
func (e *Endpoint) ParseL4Filter(l4Filter *policy.L4Filter) (policy.L4RuleContext, policy.L7RuleContext) {
	return policy.L4RuleContext{
			EndpointID: e.ID,
			Ingress:    l4Filter.Ingress,
			Proto:      uint8(l4Filter.U8Proto),
			Port:       byteorder.HostToNetwork(uint16(l4Filter.Port)).(uint16),
		}, policy.L7RuleContext{
			RedirectPort: e.lookupRedirectPortBE(l4Filter),
		}
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
	if e.Consumable == nil {
		return nil
	}
	e.Consumable.Mutex.RLock()
	defer e.Consumable.Mutex.RUnlock()
	if e.Consumable.L4Policy == nil {
		return nil
	}

	l4policy := e.Consumable.L4Policy

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
	// be dropped until the policy of the endpoint has been determined.
	if !e.PolicyCalculated && owner.PolicyEnforcement() != NeverEnforce {
		fw.WriteString("#define DROP_ALL\n")
	}

	fw.WriteString(common.FmtDefineAddress("LXC_MAC", e.LXCMAC))
	fw.WriteString(common.FmtDefineComma("LXC_IP", e.IPv6))
	if e.IPv4 != nil {
		fmt.Fprintf(fw, "#define LXC_IPV4 %#x\n", byteorder.HostSliceToNetwork(e.IPv4, reflect.Uint32))
	}
	fw.WriteString(common.FmtDefineAddress("NODE_MAC", e.NodeMAC))

	geneveOpts, err := writeGeneve(prefix, e)
	if err != nil {
		return err
	}
	fw.WriteString(common.FmtDefineArray("GENEVE_OPTS", geneveOpts))

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
		if len(e.L3Policy.Egress.IPv6PrefixCount) > 0 {
			fmt.Fprintf(fw, "#define CIDR6_EGRESS_MAP %s\n", path.Base(e.IPv6EgressMapPathLocked()))
		}
		if len(e.L3Policy.Ingress.IPv4PrefixCount) > 0 {
			fmt.Fprintf(fw, "#define CIDR4_INGRESS_MAP %s\n", path.Base(e.IPv4IngressMapPathLocked()))
		}
		if len(e.L3Policy.Egress.IPv4PrefixCount) > 0 {
			fmt.Fprintf(fw, "#define CIDR4_EGRESS_MAP %s\n", path.Base(e.IPv4EgressMapPathLocked()))
		}
	}
	fmt.Fprintf(fw, "#define CALLS_MAP %s\n", path.Base(e.CallsMapPathLocked()))
	if e.Opts.IsEnabled(OptionConntrackLocal) {
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

	fw.WriteString("#define LXC_PORT_MAPPINGS ")
	for _, m := range e.PortMap {
		// Write mappings directly in network byte order so we don't have
		// to convert it in the fast path
		fmt.Fprintf(fw, "{%#x,%#x},", byteorder.HostToNetwork(m.From), byteorder.HostToNetwork(m.To))
	}
	fw.WriteString("\n")

	if err := e.writeL4Policy(fw); err != nil {
		return err
	}

	if e.L3Policy != nil {
		ipv6Ingress, ipv4Ingress := e.L3Policy.Ingress.ToBPFData()
		ipv6Egress, ipv4Egress := e.L3Policy.Egress.ToBPFData()

		if len(ipv6Ingress) > 0 {
			fw.WriteString("#define CIDR6_INGRESS_PREFIXES ")
			for _, m := range ipv6Ingress {
				fmt.Fprintf(fw, "%d,", m)
			}
			fw.WriteString("\n")
		}
		if len(ipv6Egress) > 0 {
			fw.WriteString("#define CIDR6_EGRESS_PREFIXES ")
			for _, m := range ipv6Egress {
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
		if len(ipv4Egress) > 0 {
			fw.WriteString("#define CIDR4_EGRESS_PREFIXES ")
			for _, m := range ipv4Egress {
				fmt.Fprintf(fw, "%d,", m)
			}
			fw.WriteString("\n")
		}
	}

	return fw.Flush()
}

// FIXME: Clean this function up
func writeGeneve(prefix string, e *Endpoint) ([]byte, error) {
	// Write container options values for each available option in
	// bpf/lib/geneve.h
	// GENEVE_CLASS_EXPERIMENTAL, GENEVE_TYPE_SECLABEL

	// The int() cast here is required as otherwise Sprintf does the
	// convertion incorrectly. Looks like a golang bug.
	identityHex := fmt.Sprintf("%08x", int(e.GetIdentity()))
	err := geneve.WriteOpts(filepath.Join(prefix, "geneve_opts.cfg"), "0xffff", "0x1", "4", identityHex)
	if err != nil {
		return nil, fmt.Errorf("Could not write geneve options %s", err)
	}

	_, rawData, err := geneve.ReadOpts(filepath.Join(prefix, "geneve_opts.cfg"))
	if err != nil {
		return nil, fmt.Errorf("Could not read geneve options %s", err)
	}

	return rawData, nil
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
	keys     []lxcmap.EndpointKey
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
func (ep *epInfoCache) GetBPFKeys() []lxcmap.EndpointKey {
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
		if _, _, _, err = e.regeneratePolicy(owner, nil); err != nil {
			return 0, fmt.Errorf("Unable to regenerate policy: %s", err)
		}

		// Dry mode needs Network Policy Updates, but e.ProxyWaitGroup must not
		// be initialized, as there is no proxy ACKing the changes.
		if e.Consumable != nil {
			e.Consumable.Mutex.Lock()
			if err = e.updateNetworkPolicy(owner); err != nil {
				e.Consumable.Mutex.Unlock()
				return 0, err
			}
			e.Consumable.Mutex.Unlock()
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

	// Endpoint's identity can be changed while we are compiling
	// bpf. To be able to undo changes in case of an error we need
	// to keep a local reference to the current consumable.
	c := e.Consumable

	defer func() {
		if err != nil {
			e.Mutex.Lock()
			if createdPolicyMap {
				// Remove policy map file only if it was created
				// in this update cycle
				if c != nil {
					c.RemovePolicyMap(e.PolicyMap)
				}

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

	var (
		modifiedRules policy.SecurityIDContexts
		policyChanged bool
	)
	// Only generate & populate policy map if a security identity is set up for
	// this endpoint.
	if c != nil {
		c.AddMap(e.PolicyMap)

		// Regenerate policy and apply any options resulting in the
		// policy change.
		// This also populates e.PolicyMap.
		policyChanged, modifiedRules, _, err = e.regeneratePolicy(owner, nil)
		if err != nil {
			e.Mutex.Unlock()
			return 0, fmt.Errorf("unable to regenerate policy for '%s': %s", e.PolicyMap.String(), err)
		}

		// Walk the L4Policy for ports that require
		// an L7 redirect and add them to the endpoint; update the L4PolicyMap
		// with the redirects.
		c.Mutex.Lock()
		if c.L4Policy != nil {
			desiredRedirects, err = e.addNewRedirects(owner, c.L4Policy)
			if err != nil {
				c.Mutex.Unlock()
				e.Mutex.Unlock()
				return 0, err
			}
		}
		// Update policies after adding redirects, otherwise we will not wait for
		// acks for the first policy upates for the first added redirects.
		if err = e.updateNetworkPolicy(owner); err != nil {
			c.Mutex.Unlock()
			e.Mutex.Unlock()
			return 0, err
		}
		c.Mutex.Unlock()

		// Evaluate generated policy to see if changes to connection tracking
		// need to be made.
		//
		// policyChanged can still be true and, at the same time,
		// the modifiedRules be nil. If this happens it means
		// the L7 was changed so we need to update the
		// L3L4Policy map with the new proxyport.
		//
		// modifiedRules contains if new L4 ports were added/modified and/or
		// L3 rules were changed
		c.Mutex.RLock()
		if policyChanged &&
			modifiedRules == nil &&
			c.L4Policy != nil &&
			(len(c.L4Policy.Ingress) > 0 || len(c.L4Policy.Egress) > 0) &&
			c.L3L4Policy != nil {

			// Only update CT if the RedirectPort was changed.
			policyChanged = false

			p := *c.L3L4Policy
			for identity, l4RuleContexts := range p {
				for l4RuleContext, l7RuleContexts := range l4RuleContexts {
					var l4Filter policy.L4Filter
					var ok bool
					pp := l4RuleContext.PortProto()
					if l4RuleContext.Ingress {
						l4Filter, ok = c.L4Policy.Ingress[pp]
					} else {
						l4Filter, ok = c.L4Policy.Egress[pp]
					}
					if ok {
						redirectPort := e.lookupRedirectPortBE(&l4Filter)
						if l7RuleContexts.RedirectPort != redirectPort {
							e.getLogger().Debugf("Will update CT map entry for identity %d and proxy ID %s with redirect port %d",
								identity, l4RuleContext.ProxyID(), redirectPort)
							policyChanged = true
							l7RuleContexts.RedirectPort = redirectPort
							p[identity][l4RuleContext] = l7RuleContexts
						}
					}
				}
			}

			modifiedRules = c.L3L4Policy.DeepCopy()
		}
		c.Mutex.RUnlock()
	}

	// Generate header file specific to this endpoint for use in compiling
	// BPF programs for this endpoint.
	if err = e.writeHeaderfile(epdir, owner); err != nil {
		e.Mutex.Unlock()
		return 0, fmt.Errorf("Unable to write header file: %s", err)
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
		if len(e.L3Policy.Egress.IPv6PrefixCount) > 0 &&
			e.L3Maps.ResetBpfMap(IPv6Egress, e.IPv6EgressMapPathLocked()) == nil {
			createdIPv6EgressMap = true
			e.L3Policy.Egress.PopulateBPF(e.L3Maps[IPv6Egress])
		} else {
			e.L3Maps.DestroyBpfMap(IPv6Egress, e.IPv6EgressMapPathLocked())
		}

		if len(e.L3Policy.Ingress.IPv4PrefixCount) > 0 &&
			e.L3Maps.ResetBpfMap(IPv4Ingress, e.IPv4IngressMapPathLocked()) == nil {
			createdIPv4IngressMap = true
			e.L3Policy.Ingress.PopulateBPF(e.L3Maps[IPv4Ingress])
		} else {
			e.L3Maps.DestroyBpfMap(IPv4Ingress, e.IPv4IngressMapPathLocked())
		}
		if len(e.L3Policy.Egress.IPv4PrefixCount) > 0 &&
			e.L3Maps.ResetBpfMap(IPv4Egress, e.IPv4EgressMapPathLocked()) == nil {
			createdIPv4EgressMap = true
			e.L3Policy.Egress.PopulateBPF(e.L3Maps[IPv4Egress])
		} else {
			e.L3Maps.DestroyBpfMap(IPv4Egress, e.IPv4EgressMapPathLocked())
		}
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

	// Compile and install BPF programs for this endpoint
	err = e.runInit(libdir, rundir, epdir, epInfoCache.ifName, debug)
	if err != nil {
		return epInfoCache.revision, err
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
