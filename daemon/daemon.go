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

package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	health "github.com/cilium/cilium/cilium-health/launch"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"
	monitorLaunch "github.com/cilium/cilium/monitor/launch"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/maps/proxymap"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	policyApi "github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/proxy/logger"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/cilium/pkg/workloads"

	"github.com/go-openapi/runtime/middleware"
	"github.com/mattn/go-shellwords"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/vishvananda/netlink"
)

const (
	// ExecTimeout is the execution timeout to use in init.sh executions
	ExecTimeout = 300 * time.Second

	// AutoCIDR indicates that a CIDR should be allocated
	AutoCIDR = "auto"
)

const (
	initArgLib int = iota
	initArgRundir
	initArgIPv4NodeIP
	initArgIPv6NodeIP
	initArgMode
	initArgDevice
	initArgDevicePreFilter
	initArgModePreFilter
	initArgMTU
	initArgMax
)

// Daemon is the cilium daemon that is in charge of perform all necessary plumbing,
// monitoring when a LXC starts.
type Daemon struct {
	buildEndpointChan chan *endpoint.Request
	l7Proxy           *proxy.Proxy
	loadBalancer      *types.LoadBalancer
	policy            *policy.Repository
	preFilter         *policy.PreFilter
	// Only used for CRI-O since it does not support events.
	workloadsEventsCh chan<- *workloads.EventMessage

	statusCollectMutex      lock.RWMutex
	statusResponse          models.StatusResponse
	statusResponseTimestamp time.Time

	uniqueIDMU lock.Mutex
	uniqueID   map[uint64]bool

	nodeMonitor  *monitorLaunch.NodeMonitor
	ciliumHealth *health.CiliumHealth

	// dnsPoller is used to implement ToFQDN rules
	dnsPoller *fqdn.DNSPoller

	// k8sAPIs is a set of k8s API in use. They are setup in EnableK8sWatcher,
	// and may be disabled while the agent runs.
	// This is on this object, instead of a global, because EnableK8sWatcher is
	// on Daemon.
	k8sAPIGroups k8sAPIGroupsUsed

	// Used to synchronize generation of daemon's BPF programs and endpoint BPF
	// programs.
	compilationMutex *lock.RWMutex

	// prefixLengths tracks a mapping from CIDR prefix length to the count
	// of rules that refer to that prefix length.
	prefixLengths *counter.PrefixLengthCounter

	clustermesh *clustermesh.ClusterMesh
}

// UpdateProxyRedirect updates the redirect rules in the proxy for a particular
// endpoint using the provided L4 filter. Returns the allocated proxy port
func (d *Daemon) UpdateProxyRedirect(e *endpoint.Endpoint, l4 *policy.L4Filter, proxyWaitGroup *completion.WaitGroup) (uint16, error) {
	if d.l7Proxy == nil {
		return 0, fmt.Errorf("can't redirect, proxy disabled")
	}

	r, err := d.l7Proxy.CreateOrUpdateRedirect(l4, e.ProxyID(l4), e, proxyWaitGroup)
	if err != nil {
		return 0, err
	}

	return r.ProxyPort, nil
}

// RemoveProxyRedirect removes a previously installed proxy redirect for an
// endpoint
func (d *Daemon) RemoveProxyRedirect(e *endpoint.Endpoint, id string, proxyWaitGroup *completion.WaitGroup) error {
	if d.l7Proxy == nil {
		return nil
	}

	log.WithFields(logrus.Fields{
		logfields.EndpointID: e.ID,
		logfields.L4PolicyID: id,
	}).Debug("Removing redirect to endpoint")
	return d.l7Proxy.RemoveRedirect(id, proxyWaitGroup)
}

// UpdateNetworkPolicy adds or updates a network policy in the set
// published to L7 proxies.
func (d *Daemon) UpdateNetworkPolicy(e *endpoint.Endpoint, policy *policy.L4Policy,
	labelsMap identity.IdentityCache, deniedIngressIdentities, deniedEgressIdentities map[identity.NumericIdentity]bool, proxyWaitGroup *completion.WaitGroup) error {
	if d.l7Proxy == nil {
		return fmt.Errorf("can't update network policy, proxy disabled")
	}
	return d.l7Proxy.UpdateNetworkPolicy(e, policy, e.Options.IsEnabled(option.IngressPolicy), e.Options.IsEnabled(option.EgressPolicy),
		labelsMap, deniedIngressIdentities, deniedEgressIdentities, proxyWaitGroup)
}

// RemoveNetworkPolicy removes a network policy from the set published to
// L7 proxies.
func (d *Daemon) RemoveNetworkPolicy(e *endpoint.Endpoint) {
	if d.l7Proxy == nil {
		return
	}
	d.l7Proxy.RemoveNetworkPolicy(e)
}

// QueueEndpointBuild puts the given request in the endpoints queue for
// processing. The given request will receive 'true' in the MyTurn channel
// whenever it's its turn or false if the request was denied/canceled.
func (d *Daemon) QueueEndpointBuild(req *endpoint.Request) {
	go func(req *endpoint.Request) {
		d.uniqueIDMU.Lock()
		// We are skipping new requests, but only if the endpoint has not
		// started its build process, since the endpoint is already in queue.
		if isBuilding, exists := d.uniqueID[req.ID]; !isBuilding && exists {
			req.MyTurn <- false
		} else {
			// We mark the request "not building" state and send it to
			// the building queue.
			d.uniqueID[req.ID] = false
			d.buildEndpointChan <- req
		}
		d.uniqueIDMU.Unlock()
	}(req)
}

// RemoveFromEndpointQueue removes the endpoint from the queue.
func (d *Daemon) RemoveFromEndpointQueue(epID uint64) {
	d.uniqueIDMU.Lock()
	delete(d.uniqueID, epID)
	d.uniqueIDMU.Unlock()
}

// StartEndpointBuilders creates `nRoutines` go routines that listen on the
// `d.buildEndpointChan` for new endpoints.
func (d *Daemon) StartEndpointBuilders(nRoutines int) {
	log.WithField("count", nRoutines).Debug("Creating worker threads")
	for w := 0; w < nRoutines; w++ {
		go func() {
			for e := range d.buildEndpointChan {
				d.uniqueIDMU.Lock()
				if _, ok := d.uniqueID[e.ID]; !ok {
					// If the request is not present in the uniqueID,
					// it means the request was deleted from the queue
					// so we deny the request's turn.
					e.MyTurn <- false
					d.uniqueIDMU.Unlock()
					continue
				}
				// Set the endpoint to "building" state
				d.uniqueID[e.ID] = true
				e.MyTurn <- true
				d.uniqueIDMU.Unlock()
				// Wait for the endpoint to build
				<-e.Done
				d.uniqueIDMU.Lock()
				// In a case where the same endpoint enters the
				// building queue, while it was still being build,
				// it will be marked as `false`/"not building",
				// thus, we only delete the endpoint from the
				// queue only if it is marked as isBuilding.
				if isBuilding := d.uniqueID[e.ID]; isBuilding {
					delete(d.uniqueID, e.ID)
				}
				d.uniqueIDMU.Unlock()
			}
		}()
	}
}

// GetStateDir returns the path to the state directory
func (d *Daemon) GetStateDir() string {
	return option.Config.StateDir
}

func (d *Daemon) GetBpfDir() string {
	return option.Config.BpfDir
}

// GetPolicyRepository returns the policy repository of the daemon
func (d *Daemon) GetPolicyRepository() *policy.Repository {
	return d.policy
}

func (d *Daemon) DryModeEnabled() bool {
	return option.Config.DryMode
}

// PolicyEnforcement returns the type of policy enforcement for the daemon.
func (d *Daemon) PolicyEnforcement() string {
	return policy.GetPolicyEnabled()
}

// DebugEnabled returns if debug mode is enabled.
func (d *Daemon) DebugEnabled() bool {
	return option.Config.Opts.IsEnabled(option.Debug)
}

func (d *Daemon) writeNetdevHeader(dir string) error {

	headerPath := filepath.Join(dir, common.NetdevHeaderFileName)

	log.WithField(logfields.Path, headerPath).Debug("writing configuration")

	f, err := os.Create(headerPath)
	if err != nil {
		return fmt.Errorf("failed to open file %s for writing: %s", headerPath, err)

	}
	defer f.Close()

	fw := bufio.NewWriter(f)
	fw.WriteString(option.Config.Opts.GetFmtList())
	fw.WriteString(d.fmtPolicyEnforcementIngress())
	fw.WriteString(d.fmtPolicyEnforcementEgress())
	endpoint.WriteIPCachePrefixes(fw, d.prefixLengths.ToBPFData)

	return fw.Flush()
}

// returns #define for PolicyIngress based on the configuration of the daemon.
func (d *Daemon) fmtPolicyEnforcementIngress() string {
	if policy.GetPolicyEnabled() == option.AlwaysEnforce {
		return fmt.Sprintf("#define %s\n", option.IngressSpecPolicy.Define)
	}
	return fmt.Sprintf("#undef %s\n", option.IngressSpecPolicy.Define)
}

// returns #define for PolicyEgress based on the configuration of the daemon.
func (d *Daemon) fmtPolicyEnforcementEgress() string {
	if policy.GetPolicyEnabled() == option.AlwaysEnforce {
		return fmt.Sprintf("#define %s\n", option.EgressSpecPolicy.Define)
	}
	return fmt.Sprintf("#undef %s\n", option.EgressSpecPolicy.Define)
}

// Must be called with option.Config.EnablePolicyMU locked.
func (d *Daemon) writePreFilterHeader(dir string) error {
	headerPath := filepath.Join(dir, common.PreFilterHeaderFileName)
	log.WithField(logfields.Path, headerPath).Debug("writing configuration")
	f, err := os.Create(headerPath)
	if err != nil {
		return fmt.Errorf("failed to open file %s for writing: %s", headerPath, err)

	}
	defer f.Close()
	fw := bufio.NewWriter(f)
	fmt.Fprint(fw, "/*\n")
	fmt.Fprintf(fw, " * XDP device: %s\n", option.Config.DevicePreFilter)
	fmt.Fprintf(fw, " * XDP mode: %s\n", option.Config.ModePreFilter)
	fmt.Fprint(fw, " */\n\n")
	d.preFilter.WriteConfig(fw)
	return fw.Flush()
}

func (d *Daemon) setHostAddresses() error {
	l, err := netlink.LinkByName(option.Config.LBInterface)
	if err != nil {
		return fmt.Errorf("unable to get network device %s: %s", option.Config.Device, err)
	}

	getAddr := func(netLinkFamily int) (net.IP, error) {
		addrs, err := netlink.AddrList(l, netLinkFamily)
		if err != nil {
			return nil, fmt.Errorf("error while getting %s's addresses: %s", option.Config.Device, err)
		}
		for _, possibleAddr := range addrs {
			if netlink.Scope(possibleAddr.Scope) == netlink.SCOPE_UNIVERSE {
				return possibleAddr.IP, nil
			}
		}
		return nil, nil
	}

	if !option.Config.IPv4Disabled {
		hostV4Addr, err := getAddr(netlink.FAMILY_V4)
		if err != nil {
			return err
		}
		if hostV4Addr != nil {
			option.Config.HostV4Addr = hostV4Addr
			log.Infof("Using IPv4 host address: %s", option.Config.HostV4Addr)
		}
	}
	hostV6Addr, err := getAddr(netlink.FAMILY_V6)
	if err != nil {
		return err
	}
	if hostV6Addr != nil {
		option.Config.HostV6Addr = hostV6Addr
		log.Infof("Using IPv6 host address: %s", option.Config.HostV6Addr)
	}
	return nil
}

func runProg(prog string, args []string, quiet bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), ExecTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, prog, args...).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		cmd := fmt.Sprintf("%s %s", prog, strings.Join(args, " "))
		log.WithField("cmd", cmd).Error("Command execution failed: Timeout")
		return fmt.Errorf("Command execution failed: Timeout for %s %s", prog, args)
	}
	if err != nil {
		if !quiet {
			cmd := fmt.Sprintf("%s %s", prog, strings.Join(args, " "))
			log.WithError(err).WithField("cmd", cmd).Error("Command execution failed")

			scanner := bufio.NewScanner(bytes.NewReader(out))
			for scanner.Scan() {
				log.Warn(scanner.Text())
			}
		}
	}

	return err
}

const (
	ciliumOutputChain     = "CILIUM_OUTPUT"
	ciliumPostNatChain    = "CILIUM_POST"
	ciliumPostMangleChain = "CILIUM_POST_mangle"
	ciliumForwardChain    = "CILIUM_FORWARD"
	feederDescription     = "cilium-feeder:"
)

type customChain struct {
	name       string
	table      string
	hook       string
	feederArgs []string
}

func getFeedRule(name, args string) []string {
	ruleTail := []string{"-m", "comment", "--comment", feederDescription + " " + name, "-j", name}
	if args == "" {
		return ruleTail
	}
	argsList, err := shellwords.Parse(args)
	if err != nil {
		log.WithError(err).WithField(logfields.Object, args).Fatal("Unable to parse rule into argument slice")
	}
	return append(argsList, ruleTail...)
}

func (c *customChain) add() error {
	return runProg("iptables", []string{"-t", c.table, "-N", c.name}, false)
}

func removeCiliumRules(table string) {
	prog := "iptables"
	args := []string{"-t", table, "-S"}

	ctx, cancel := context.WithTimeout(context.Background(), ExecTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, prog, args...).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		cmd := fmt.Sprintf("%s %s", prog, strings.Join(args, " "))
		log.WithField("cmd", cmd).Error("Command execution failed: Timeout")
		return
	}
	if err != nil {
		cmd := fmt.Sprintf("%s %s", prog, strings.Join(args, " "))
		log.WithError(err).WithField("cmd", cmd).Warn("Command execution failed")
		return
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		rule := scanner.Text()
		log.WithField(logfields.Object, logfields.Repr(rule)).Debug("Considering removing iptables rule")

		if strings.Contains(strings.ToLower(rule), "cilium") &&
			(strings.HasPrefix(rule, "-A") || strings.HasPrefix(rule, "-I")) {
			// From: -A POSTROUTING -m comment [...]
			// To:   -D POSTROUTING -m comment [...]
			ruleAsArgs, err := shellwords.Parse(strings.Replace(rule, "-A", "-D", 1))
			if err != nil {
				log.WithError(err).WithField(logfields.Object, rule).Warn("Unable to parse iptables rule into slice. Leaving rule behind.")
				continue
			}

			deleteRule := append([]string{"-t", table}, ruleAsArgs...)
			log.WithField(logfields.Object, logfields.Repr(deleteRule)).Debug("Removing iptables rule")
			err = runProg("iptables", deleteRule, true)
			if err != nil {
				log.WithError(err).WithField(logfields.Object, rule).Warn("Unable to delete Cilium iptables rule")
			}
		}
	}
}

func (c *customChain) remove() {
	runProg("iptables", []string{
		"-t", c.table,
		"-F", c.name}, true)

	runProg("iptables", []string{
		"-t", c.table,
		"-X", c.name}, true)
}

func (c *customChain) installFeeder() error {
	for _, feedArgs := range c.feederArgs {
		err := runProg("iptables", append([]string{"-t", c.table, "-A", c.hook}, getFeedRule(c.name, feedArgs)...), true)
		if err != nil {
			return err
		}
	}
	return nil
}

// ciliumChains is the list of custom iptables chain used by Cilium. Custom
// chains are used to allow for simple replacements of all rules.
//
// WARNING: If you change or remove any of the feeder rules you have to ensure
// that the old feeder rules is also removed on agent start, otherwise,
// flushing and removing the custom chains will fail.
var ciliumChains = []customChain{
	{
		name:       ciliumOutputChain,
		table:      "filter",
		hook:       "OUTPUT",
		feederArgs: []string{""},
	},
	{
		name:       ciliumPostNatChain,
		table:      "nat",
		hook:       "POSTROUTING",
		feederArgs: []string{""},
	},
	{
		name:       ciliumPostMangleChain,
		table:      "mangle",
		hook:       "POSTROUTING",
		feederArgs: []string{""},
	},
	{
		name:       ciliumForwardChain,
		table:      "filter",
		hook:       "FORWARD",
		feederArgs: []string{""},
	},
}

func (d *Daemon) removeIptablesRules() {
	tables := []string{"nat", "mangle", "raw", "filter"}
	for _, t := range tables {
		removeCiliumRules(t)
	}

	for _, c := range ciliumChains {
		c.remove()
	}
}

func (d *Daemon) installIptablesRules() error {
	for _, c := range ciliumChains {
		if err := c.add(); err != nil {
			return fmt.Errorf("cannot add custom chain %s: %s", c.name, err)
		}
	}

	// Clear the Kubernetes masquerading mark bit to skip source PAT
	// performed by kube-proxy for all packets destined for Cilium. Cilium
	// installs a dedicated rule which does the source PAT to the right
	// source IP.
	clearMasqBit := fmt.Sprintf("%#08x/%#08x", 0, proxy.MagicMarkK8sMasq)
	if err := runProg("iptables", []string{
		"-t", "mangle",
		"-A", ciliumPostMangleChain,
		"-o", "cilium_host",
		"-m", "comment", "--comment", "cilium: clear masq bit for pkts to cilium_host",
		"-j", "MARK", "--set-xmark", clearMasqBit}, false); err != nil {
		return err
	}

	// kube-proxy does not change the default policy of the FORWARD chain
	// which means that while packets to services are properly DNAT'ed,
	// they are later dropped in the FORWARD chain. The issue has been
	// resolved in #52569 and will be fixed in k8s >= 1.8. The following is
	// a workaround for earlier Kubernetes versions.
	//
	// Accept all packets in FORWARD chain that are going to cilium_host
	// with a destination IP in the cluster range.
	if err := runProg("iptables", []string{
		"-A", ciliumForwardChain,
		"-d", node.GetIPv4ClusterRange().String(),
		"-o", "cilium_host",
		"-m", "comment", "--comment", "cilium: any->cluster on cilium_host forward accept",
		"-j", "ACCEPT"}, false); err != nil {
		return err
	}

	// Accept all packets in the FORWARD chain that are coming from the
	// cilium_host interface with a source IP in the cluster range.
	if err := runProg("iptables", []string{
		"-A", ciliumForwardChain,
		"-s", node.GetIPv4ClusterRange().String(),
		"-m", "comment", "--comment", "cilium: cluster->any forward accept",
		"-j", "ACCEPT"}, false); err != nil {
		return err
	}

	// Mark all packets sourced from processes running on the host with a
	// special marker so that we can differentiate traffic sourced locally
	// vs. traffic from the outside world that was masqueraded to appear
	// like it's from the host.
	//
	// Originally we set this mark only for traffic destined to the
	// cilium_host device, to ensure that any traffic directly reaching
	// to a Cilium-managed IP could be classified as from the host.
	//
	// However, there's another case where a local process attempts to
	// reach a service IP which is backed by a Cilium-managed pod. The
	// service implementation is outside of Cilium's control, for example,
	// handled by kube-proxy. We can tag even this traffic with a magic
	// mark, then when the service implementation proxies it back into
	// Cilium the BPF will see this mark and understand that the packet
	// originated from the host.
	matchFromProxy := fmt.Sprintf("%#08x/%#08x", proxy.MagicMarkIsProxy, proxy.MagicMarkProxyMask)
	markAsFromHost := fmt.Sprintf("%#08x/%#08x", proxy.MagicMarkHost, proxy.MagicMarkHostMask)
	if err := runProg("iptables", []string{
		"-t", "filter",
		"-A", ciliumOutputChain,
		"-m", "mark", "!", "--mark", matchFromProxy, // Don't match proxy traffic
		"-m", "comment", "--comment", "cilium: host->any mark as from host",
		"-j", "MARK", "--set-xmark", markAsFromHost}, false); err != nil {
		return err
	}

	if masquerade {
		ingressSnatSrcAddrExclusion := node.GetHostMasqueradeIPv4().String()
		if option.Config.Tunnel == option.TunnelDisabled {
			ingressSnatSrcAddrExclusion = node.GetIPv4ClusterRange().String()
		}

		// Masquerade all traffic from the host into the cilium_host
		// interface if the source is not the internal IP
		//
		// The following conditions must be met:
		// * Must be targeted for the cilium_host interface
		// * Tunnel mode:
		//   * May not already be originating from the masquerade IP
		// * Non-tunnel mode:
		//   * May not orignate from any IP inside of the cluster range
		if err := runProg("iptables", []string{
			"-t", "nat",
			"-A", ciliumPostNatChain,
			"!", "-s", ingressSnatSrcAddrExclusion,
			"-o", "cilium_host",
			"-m", "comment", "--comment", "cilium host->cluster masquerade",
			"-j", "SNAT", "--to-source", node.GetHostMasqueradeIPv4().String()}, false); err != nil {
			return err
		}

		egressSnatDstAddrExclusion := node.GetIPv4AllocRange().String()
		if option.Config.Tunnel == option.TunnelDisabled {
			egressSnatDstAddrExclusion = node.GetIPv4ClusterRange().String()
		}

		// Masquerade all egress traffic leaving the node
		//
		// The following conditions must be met:
		// * May not leave on a cilium_ interface, this excludes all
		//   tunnel traffic
		// * Must originate from an IP in the local allocation range
		// * Tunnel mode:
		//   * May not be targeted to an IP in the local allocation
		//     range
		// * Non-tunnel mode:
		//   * May not be targeted to an IP in the cluster range
		if err := runProg("iptables", []string{
			"-t", "nat",
			"-A", "CILIUM_POST",
			"-s", node.GetIPv4AllocRange().String(),
			"!", "-d", egressSnatDstAddrExclusion,
			"!", "-o", "cilium_+",
			"-m", "comment", "--comment", "cilium masquerade non-cluster",
			"-j", "MASQUERADE"}, false); err != nil {
			return err
		}
	}

	for _, c := range ciliumChains {
		if err := c.installFeeder(); err != nil {
			return fmt.Errorf("cannot install feeder rule %s: %s", c.feederArgs, err)
		}
	}

	return nil
}

// GetCompilationLock returns the mutex responsible for synchronizing compilation
// of BPF programs.
func (d *Daemon) GetCompilationLock() *lock.RWMutex {
	return d.compilationMutex
}

func (d *Daemon) compileBase() error {
	var args []string
	var mode string
	var ret error

	args = make([]string, initArgMax)

	// Lock so that endpoints cannot be built while we are compile base programs.
	d.compilationMutex.Lock()
	defer d.compilationMutex.Unlock()

	if err := d.writeNetdevHeader("./"); err != nil {
		log.WithError(err).Warn("Unable to write netdev header")
		return err
	}

	scopedLog := log.WithField(logfields.XDPDevice, option.Config.DevicePreFilter)
	if option.Config.DevicePreFilter != "undefined" {
		if err := policy.ProbePreFilter(option.Config.DevicePreFilter, option.Config.ModePreFilter); err != nil {
			scopedLog.WithError(err).Warn("Turning off prefilter")
			option.Config.DevicePreFilter = "undefined"
		}
	}
	if option.Config.DevicePreFilter != "undefined" {
		if d.preFilter, ret = policy.NewPreFilter(); ret != nil {
			scopedLog.WithError(ret).Warn("Unable to init prefilter")
			return ret
		}

		if err := d.writePreFilterHeader("./"); err != nil {
			scopedLog.WithError(err).Warn("Unable to write prefilter header")
			return err
		}

		args[initArgDevicePreFilter] = option.Config.DevicePreFilter
		args[initArgModePreFilter] = option.Config.ModePreFilter
	}

	args[initArgLib] = option.Config.BpfDir
	args[initArgRundir] = option.Config.StateDir
	args[initArgIPv4NodeIP] = node.GetInternalIPv4().String()
	args[initArgIPv6NodeIP] = node.GetIPv6().String()
	args[initArgMTU] = fmt.Sprintf("%d", mtu.GetDeviceMTU())

	if option.Config.Device != "undefined" {
		_, err := netlink.LinkByName(option.Config.Device)
		if err != nil {
			log.WithError(err).WithField("device", option.Config.Device).Warn("Link does not exist")
			return err
		}

		if option.Config.IsLBEnabled() {
			if option.Config.Device != option.Config.LBInterface {
				//FIXME: allow different interfaces
				return fmt.Errorf("Unable to have an interface for LB mode different than snooping interface")
			}
			if err := d.setHostAddresses(); err != nil {
				return err
			}
			mode = "lb"
		} else {
			mode = "direct"
		}

		args[initArgMode] = mode
		args[initArgDevice] = option.Config.Device

		args = append(args, option.Config.Device)
	} else {
		if option.Config.IsLBEnabled() {
			//FIXME: allow LBMode in tunnel
			return fmt.Errorf("Unable to run LB mode with tunnel mode")
		}

		args[initArgMode] = option.Config.Tunnel
	}

	prog := filepath.Join(option.Config.BpfDir, "init.sh")
	ctx, cancel := context.WithTimeout(context.Background(), ExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, prog, args...)
	cmd.Env = bpf.Environment()
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		cmd := fmt.Sprintf("%s %s", prog, strings.Join(args, " "))
		log.WithField("cmd", cmd).Error("Command execution failed: Timeout")
		return fmt.Errorf("Command execution failed: Timeout for %s %s", prog, args)
	}
	if err != nil {
		cmd := fmt.Sprintf("%s %s", prog, strings.Join(args, " "))
		log.WithField("cmd", cmd).Error("Command execution failed")

		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			log.Warn(scanner.Text())
		}
		return err
	}

	ipam.ReserveLocalRoutes()
	node.InstallHostRoutes()

	if !option.Config.IPv4Disabled {
		// Always remove masquerade rule and then re-add it if required
		d.removeIptablesRules()
		if err := d.installIptablesRules(); err != nil {
			return err
		}
	}

	log.Info("Setting sysctl net.core.bpf_jit_enable=1")
	log.Info("Setting sysctl net.ipv4.conf.all.rp_filter=0")
	log.Info("Setting sysctl net.ipv6.conf.all.disable_ipv6=0")

	return nil
}

func (d *Daemon) init() error {

	var err error

	globalsDir := option.Config.GetGlobalsDir()
	if err := os.MkdirAll(globalsDir, defaults.RuntimePathRights); err != nil {
		log.WithError(err).WithField(logfields.Path, globalsDir).Fatal("Could not create runtime directory")
	}

	if err := os.Chdir(option.Config.StateDir); err != nil {
		log.WithError(err).WithField(logfields.Path, option.Config.StateDir).Fatal("Could not change to runtime directory")
	}

	if err = createNodeConfigHeaderfile(); err != nil {
		return nil
	}

	if !d.DryModeEnabled() {
		// Validate existing map paths before attempting BPF compile.
		if err = d.validateExistingMaps(); err != nil {
			log.WithError(err).Error("Error while validating maps")
			return err
		}

		if err := d.compileBase(); err != nil {
			return err
		}

		// Clean all endpoint entries
		if err := lxcmap.LXCMap.DeleteAll(); err != nil {
			return err
		}

		// Set up the list of IPCache listeners in the daemon, to be
		// used by syncLXCMap().
		ipcache.IPIdentityCache.SetListeners([]ipcache.IPIdentityMappingListener{
			&envoy.NetworkPolicyHostsCache, d})

		// Insert local host entries to bpf maps
		if err := d.syncLXCMap(); err != nil {
			return err
		}

		// Start the controller for periodic sync
		// The purpose of the controller is to ensure that the host entries are
		// reinserted to the bpf maps if they are ever removed from them.
		// TODO: Determine if we can get rid of this when we have more rigorous
		//       desired/realized state implementation for the bpf maps.
		controller.NewManager().UpdateController("lxcmap-bpf-host-sync",
			controller.ControllerParams{
				DoFunc:      func() error { return d.syncLXCMap() },
				RunInterval: 5 * time.Second,
			})

		// Start the controller for periodic sync of the metrics map with
		// the prometheus server.
		controller.NewManager().UpdateController("metricsmap-bpf-prom-sync",
			controller.ControllerParams{
				DoFunc:      metricsmap.SyncMetricsMap,
				RunInterval: 5 * time.Second,
			})

		if _, err := lbmap.Service6Map.OpenOrCreate(); err != nil {
			return err
		}
		if _, err := lbmap.RevNat6Map.OpenOrCreate(); err != nil {
			return err
		}
		if _, err := lbmap.RRSeq6Map.OpenOrCreate(); err != nil {
			return err
		}
		if !option.Config.IPv4Disabled {
			if _, err := lbmap.Service4Map.OpenOrCreate(); err != nil {
				return err
			}
			if _, err := lbmap.RevNat4Map.OpenOrCreate(); err != nil {
				return err
			}
			if _, err := lbmap.RRSeq4Map.OpenOrCreate(); err != nil {
				return err
			}
		}
		// Clean all lb entries
		if !option.Config.RestoreState {
			log.Debug("cleaning up all BPF LB maps")

			d.loadBalancer.BPFMapMU.Lock()
			defer d.loadBalancer.BPFMapMU.Unlock()

			if err := lbmap.Service6Map.DeleteAll(); err != nil {
				return err
			}
			if err := d.RevNATDeleteAll(); err != nil {
				return err
			}
			if err := lbmap.RRSeq6Map.DeleteAll(); err != nil {
				return err
			}

			if !option.Config.IPv4Disabled {
				if err := lbmap.Service4Map.DeleteAll(); err != nil {
					return err
				}
				if err := lbmap.RRSeq4Map.DeleteAll(); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func createNodeConfigHeaderfile() error {
	nodeConfigPath := option.Config.GetNodeConfigPath()
	f, err := os.Create(nodeConfigPath)
	if err != nil {
		log.WithError(err).WithField(logfields.Path, nodeConfigPath).Fatal("Failed to create node configuration file")
		return err

	}
	fw := bufio.NewWriter(f)

	routerIP := node.GetIPv6Router()
	hostIP := node.GetIPv6()

	fmt.Fprintf(fw, ""+
		"/*\n"+
		" * Node-IPv6: %s\n"+
		" * Router-IPv6: %s\n",
		hostIP.String(), routerIP.String())

	if option.Config.IPv4Disabled {
		fw.WriteString(" */\n\n")
	} else {
		fmt.Fprintf(fw, ""+
			" * Host-IPv4: %s\n"+
			" */\n\n"+
			"#define ENABLE_IPV4\n",
			node.GetInternalIPv4().String())
	}

	fw.WriteString(common.FmtDefineComma("ROUTER_IP", routerIP))

	if !option.Config.IPv4Disabled {
		ipv4GW := node.GetInternalIPv4()
		loopbackIPv4 := node.GetIPv4Loopback()
		fmt.Fprintf(fw, "#define IPV4_GATEWAY %#x\n", byteorder.HostSliceToNetwork(ipv4GW, reflect.Uint32).(uint32))
		fmt.Fprintf(fw, "#define IPV4_LOOPBACK %#x\n", byteorder.HostSliceToNetwork(loopbackIPv4, reflect.Uint32).(uint32))
	} else {
		// FIXME: Workaround so the bpf program compiles
		fmt.Fprintf(fw, "#define IPV4_GATEWAY %#x\n", 0)
		fmt.Fprintf(fw, "#define IPV4_LOOPBACK %#x\n", 0)
	}

	ipv4Range := node.GetIPv4AllocRange()
	fmt.Fprintf(fw, "#define IPV4_MASK %#x\n", byteorder.HostSliceToNetwork(ipv4Range.Mask, reflect.Uint32).(uint32))

	ipv4ClusterRange := node.GetIPv4ClusterRange()
	fmt.Fprintf(fw, "#define IPV4_CLUSTER_RANGE %#x\n", byteorder.HostSliceToNetwork(ipv4ClusterRange.IP, reflect.Uint32).(uint32))
	fmt.Fprintf(fw, "#define IPV4_CLUSTER_MASK %#x\n", byteorder.HostSliceToNetwork(ipv4ClusterRange.Mask, reflect.Uint32).(uint32))

	if nat46Range := option.Config.NAT46Prefix; nat46Range != nil {
		fw.WriteString(common.FmtDefineAddress("NAT46_PREFIX", nat46Range.IP))
	}

	fw.WriteString(common.FmtDefineComma("HOST_IP", hostIP))
	fmt.Fprintf(fw, "#define HOST_ID %d\n", identity.GetReservedID(labels.IDNameHost))
	fmt.Fprintf(fw, "#define WORLD_ID %d\n", identity.GetReservedID(labels.IDNameWorld))
	fmt.Fprintf(fw, "#define CLUSTER_ID %d\n", identity.GetReservedID(labels.IDNameCluster))
	fmt.Fprintf(fw, "#define HEALTH_ID %d\n", identity.GetReservedID(labels.IDNameHealth))
	fmt.Fprintf(fw, "#define INIT_ID %d\n", identity.GetReservedID(labels.IDNameInit))
	fmt.Fprintf(fw, "#define LB_RR_MAX_SEQ %d\n", lbmap.MaxSeq)
	fmt.Fprintf(fw, "#define CILIUM_LB_MAP_MAX_ENTRIES %d\n", lbmap.MaxEntries)
	fmt.Fprintf(fw, "#define TUNNEL_ENDPOINT_MAP_SIZE %d\n", tunnel.MaxEntries)
	fmt.Fprintf(fw, "#define PROXY_MAP_SIZE %d\n", proxymap.MaxEntries)
	fmt.Fprintf(fw, "#define ENDPOINTS_MAP_SIZE %d\n", lxcmap.MaxEntries)
	fmt.Fprintf(fw, "#define METRICS_MAP_SIZE %d\n", metricsmap.MaxEntries)
	fmt.Fprintf(fw, "#define POLICY_MAP_SIZE %d\n", policymap.MaxEntries)
	fmt.Fprintf(fw, "#define IPCACHE_MAP_SIZE %d\n", ipcachemap.MaxEntries)
	fmt.Fprintf(fw, "#define POLICY_PROG_MAP_SIZE %d\n", policymap.ProgArrayMaxEntries)

	fmt.Fprintf(fw, "#define TRACE_PAYLOAD_LEN %dULL\n", tracePayloadLen)

	fw.Flush()
	f.Close()

	return nil
}

// syncLXCMap adds local host enties to bpf lxcmap, as well as
// ipcache, if needed, and also notifies the daemon and network policy
// hosts cache if changes were made.
func (d *Daemon) syncLXCMap() error {
	// TODO: Update addresses first, in case node addressing has changed.
	// TODO: Once these start changing on runtime, figure out the locking strategy.
	// TODO: Delete stale host entries from the lxcmap.
	specialIdentities := []identity.IPIdentityPair{
		{
			IP: node.GetInternalIPv4(),
			ID: identity.ReservedIdentityHost,
		},
		{
			IP: node.GetExternalIPv4(),
			ID: identity.ReservedIdentityHost,
		},
		{
			IP: node.GetIPv6(),
			ID: identity.ReservedIdentityHost,
		},
		{
			IP: node.GetIPv6Router(),
			ID: identity.ReservedIdentityHost,
		},
		{
			IP:   node.GetIPv6ClusterRange().IP,
			Mask: node.GetIPv6ClusterRange().Mask,
			ID:   identity.ReservedIdentityCluster,
		},
		{
			IP:   node.GetIPv4ClusterRange().IP,
			Mask: node.GetIPv4ClusterRange().Mask,
			ID:   identity.ReservedIdentityCluster,
		},
		{
			IP:   net.IPv4zero,
			Mask: net.CIDRMask(0, net.IPv4len*8),
			ID:   identity.ReservedIdentityWorld,
		},
		{
			IP:   net.IPv6zero,
			Mask: net.CIDRMask(0, net.IPv6len*8),
			ID:   identity.ReservedIdentityWorld,
		},
	}

	for _, ipIDPair := range specialIdentities {
		isHost := ipIDPair.ID == identity.ReservedIdentityHost
		if isHost {
			added, err := lxcmap.SyncHostEntry(ipIDPair.IP)
			if err != nil {
				return fmt.Errorf("Unable to add host entry to endpoint map: %s", err)
			}
			if added {
				log.WithField(logfields.IPAddr, ipIDPair.IP).Debugf("Added local ip to endpoint map")
			}
		}
		// Upsert will not propagate (reserved:foo->ID) mappings across the cluster,
		// and we specifically don't want to do so.
		ipcache.IPIdentityCache.Upsert(ipIDPair.PrefixString(), nil, ipcache.Identity{
			ID:     ipIDPair.ID,
			Source: ipcache.FromAgentLocal,
		})
	}
	return nil
}

func createIPNet(ones, bits int) *net.IPNet {
	return &net.IPNet{
		Mask: net.CIDRMask(ones, bits),
	}
}

// createPrefixLengthCounter wraps around the counter library, providing
// references to prefix lengths that will always be present.
func createPrefixLengthCounter() *counter.PrefixLengthCounter {
	counter := counter.NewPrefixLengthCounter(ipcachemap.IPCache.GetMaxPrefixLengths())

	// This is a bit ugly, but there's not a great way to define an IPNet
	// without parsing strings, etc.
	defaultPrefixes := []*net.IPNet{
		// IPv4
		createIPNet(0, net.IPv4len*8),                     // world
		createIPNet(v4ClusterCidrMaskSize, net.IPv4len*8), // cluster
		createIPNet(net.IPv4len*8, net.IPv4len*8),         // hosts

		// IPv6
		createIPNet(0, net.IPv6len*8), // world
		createIPNet(node.DefaultIPv6ClusterPrefixLen, net.IPv6len*8),
		createIPNet(net.IPv6len*8, net.IPv6len*8), // hosts
	}
	_, err := counter.Add(defaultPrefixes)
	if err != nil {
		log.WithError(err).Fatal("Failed to create default prefix lengths")
	}
	return counter
}

// NewDaemon creates and returns a new Daemon with the parameters set in c.
func NewDaemon() (*Daemon, error) {
	// Validate the daemon specific global options
	if err := option.Config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid daemon configuration: %s", err)
	}

	if err := workloads.Setup(option.Config.Workloads, map[string]string{}); err != nil {
		return nil, fmt.Errorf("unable to setup workload: %s", err)
	}

	lb := types.NewLoadBalancer()

	d := Daemon{
		loadBalancer:  lb,
		policy:        policy.NewPolicyRepository(),
		uniqueID:      map[uint64]bool{},
		nodeMonitor:   monitorLaunch.NewNodeMonitor(),
		prefixLengths: createPrefixLengthCounter(),

		// FIXME
		// The channel size has to be set to the maximum number of
		// possible endpoints to guarantee that enqueueing into the
		// build queue never blocks.
		buildEndpointChan: make(chan *endpoint.Request, lxcmap.MaxEntries),
		compilationMutex:  new(lock.RWMutex),
	}

	workloads.Init(&d)

	// Clear previous leftovers before listening for new requests
	log.Info("Clearing leftover Cilium veths")
	err := d.clearCiliumVeths()
	if err != nil {
		log.WithError(err).Debug("Unable to clean leftover veths")
	}

	// Create at least 4 worker threads or the same amount as there are
	// CPUs.
	log.Info("Launching endpoint builder workers")
	d.StartEndpointBuilders(numWorkerThreads())

	if k8s.IsEnabled() {
		if err := k8s.Init(); err != nil {
			log.WithError(err).Fatal("Unable to initialize Kubernetes subsystem")
		}

		// Kubernetes demands that the localhost can always reach local
		// pods. Therefore unless the AllowLocalhost policy is set to a
		// specific mode, always allow localhost to reach local
		// endpoints.
		if option.Config.AllowLocalhost == option.AllowLocalhostAuto {
			option.Config.AllowLocalhost = option.AllowLocalhostAlways
			log.Info("k8s mode: Allowing localhost to reach local endpoints")
		}

		// In Cilium 1.0, due to limitations on the data path, traffic
		// from the outside world on ingress was treated as though it
		// was from the host for policy purposes. In order to not break
		// existing policies, this option retains the behavior.
		if viper.GetString("k8s-legacy-host-allows-world") != "false" {
			option.Config.HostAllowsWorld = true
			log.Warn("k8s mode: Configuring ingress policy for host to also allow from world. For more information, see https://cilium.link/host-vs-world")
		}
	}

	// If the device has been specified, the IPv4AllocPrefix and the
	// IPv6AllocPrefix were already allocated before the k8s.Init().
	//
	// If the device hasn't been specified, k8s.Init() allocated the
	// IPv4AllocPrefix and the IPv6AllocPrefix from k8s node annotations.
	//
	// If k8s.Init() failed to retrieve the IPv4AllocPrefix we can try to derive
	// it from an existing node_config.h file or from previous cilium_host
	// interfaces.
	//
	// Then, we will calculate the IPv4 or IPv6 alloc prefix based on the IPv6
	// or IPv4 alloc prefix, respectively, retrieved by k8s node annotations.
	log.Info("Initializing node addressing")

	if err := node.AutoComplete(); err != nil {
		log.WithError(err).Fatal("Cannot autocomplete node addresses")
	}

	node.SetIPv4ClusterCidrMaskSize(v4ClusterCidrMaskSize)

	if v4Prefix != AutoCIDR {
		_, net, err := net.ParseCIDR(v4Prefix)
		if err != nil {
			log.WithError(err).WithField(logfields.V4Prefix, v4Prefix).Fatal("Invalid IPv4 allocation prefix")
		}
		node.SetIPv4AllocRange(net)
	}

	if v4ServicePrefix != AutoCIDR {
		_, ipnet, err := net.ParseCIDR(v4ServicePrefix)
		if err != nil {
			log.WithError(err).WithField(logfields.V4Prefix, v4ServicePrefix).Fatal("Invalid IPv4 service prefix")
		}

		node.AddAuxPrefix(ipnet)
	}

	if v6Prefix != AutoCIDR {
		_, net, err := net.ParseCIDR(v6Prefix)
		if err != nil {
			log.WithError(err).WithField(logfields.V6Prefix, v6ServicePrefix).Fatal("Invalid IPv6 allocation prefix")
		}

		if err := node.SetIPv6NodeRange(net); err != nil {
			log.WithError(err).WithField(logfields.V6Prefix, net).Fatal("Invalid per node IPv6 allocation prefix")
		}
	}

	if v6ServicePrefix != AutoCIDR {
		_, ipnet, err := net.ParseCIDR(v6ServicePrefix)
		if err != nil {
			log.WithError(err).WithField(logfields.V6Prefix, v6ServicePrefix).Fatal("Invalid IPv6 service prefix")
		}

		node.AddAuxPrefix(ipnet)
	}

	if k8s.IsEnabled() {
		log.Info("Annotating k8s node with CIDR ranges")
		err := k8s.AnnotateNode(k8s.Client(), node.GetName(),
			node.GetIPv4AllocRange(), node.GetIPv6NodeRange(),
			nil, nil, node.GetInternalIPv4())
		if err != nil {
			log.WithError(err).Warning("Cannot annotate k8s node with CIDR range")
		}
	}

	// Set up ipam conf after init() because we might be running d.conf.KVStoreIPv4Registration
	log.Info("Initializing IPAM")
	ipam.Init()

	// restore endpoints before any IPs are allocated to avoid eventual IP
	// conflicts later on, otherwise any IP conflict will result in the
	// endpoint not being able to be restored.
	restoredEndpoints, err := d.restoreOldEndpoints(option.Config.StateDir, true)
	if err != nil {
		log.WithError(err).Error("Unable to restore existing endpoints")
	}

	switch err := ipam.AllocateInternalIPs(); err.(type) {
	case ipam.ErrAllocation:
		if v4Prefix == AutoCIDR || v6Prefix == AutoCIDR {
			log.WithError(err).Fatalf(
				"The allocation CIDR is different from the previous cilium instance. " +
					"This error is most likely caused by a temporary network disruption to the kube-apiserver " +
					"that prevent Cilium from retrieve the node's IPv4/IPv6 allocation range. " +
					"If you believe the allocation range is supposed to be different you need to clean " +
					"up all Cilium state with the `cilium cleanup` command on this node. Be aware " +
					"this will cause network disruption for all existing containers managed by Cilium " +
					"running on this node and you will have to restart them.")
		} else {
			log.WithError(err).Fatalf(
				"The allocation CIDR is different from the previous cilium instance. " +
					"If you believe the allocation range is supposed to be different you need to clean " +
					"up all Cilium state with the `cilium cleanup` command on this node. Be aware " +
					"this will cause network disruption for all existing containers managed by Cilium " +
					"running on this node and you will have to restart them.")
		}
	case error:
		log.WithError(err).Fatal("IPAM init failed")
	}

	log.Info("Validating configured node address ranges")
	if err := node.ValidatePostInit(); err != nil {
		log.WithError(err).Fatal("postinit failed")
	}
	log.Info("Addressing information:")
	log.Infof("  Cluster-Name: %s", option.Config.ClusterName)
	log.Infof("  Cluster-ID: %d", option.Config.ClusterID)
	log.Infof("  Local node-name: %s", node.GetName())
	log.Infof("  Node-IPv6: %s", node.GetIPv6())
	log.Infof("  External-Node IPv4: %s", node.GetExternalIPv4())
	log.Infof("  Internal-Node IPv4: %s", node.GetInternalIPv4())
	log.Infof("  Cluster IPv6 prefix: %s", node.GetIPv6ClusterRange())
	log.Infof("  Cluster IPv4 prefix: %s", node.GetIPv4ClusterRange())
	log.Infof("  IPv6 node prefix: %s", node.GetIPv6NodeRange())
	log.Infof("  IPv6 allocation prefix: %s", node.GetIPv6AllocRange())
	log.Infof("  IPv4 allocation prefix: %s", node.GetIPv4AllocRange())
	log.Infof("  IPv6 router address: %s", node.GetIPv6Router())

	if !option.Config.IPv4Disabled {
		// Allocate IPv4 service loopback IP
		loopbackIPv4, _, err := ipam.AllocateNext("ipv4")
		if err != nil {
			return nil, fmt.Errorf("Unable to reserve IPv4 loopback address: %s", err)
		}
		node.SetIPv4Loopback(loopbackIPv4)
		log.Infof("  Loopback IPv4: %s", node.GetIPv4Loopback().String())
	}

	if err := node.ConfigureLocalNode(); err != nil {
		log.WithError(err).Fatal("Unable to initialize local node")
	}

	if path := option.Config.ClusterMeshConfig; path != "" {
		log.WithField("path", path).Info("Enabling inter cluster routing")
		clustermesh, err := clustermesh.NewClusterMesh(clustermesh.Configuration{
			Name:            "clustermesh",
			ConfigDirectory: path,
			NodeKeyCreator:  node.KeyCreator,
		})
		if err != nil {
			log.WithError(err).Fatal("Unable to initialize clustermesh")
		}

		d.clustermesh = clustermesh
	}

	// This needs to be done after the node addressing has been configured
	// as the node address is required as sufix
	identity.InitIdentityAllocator(&d)

	if err = d.init(); err != nil {
		log.WithError(err).Error("Error while initializing daemon")
		return nil, err
	}

	// Start watcher for endpoint IP --> identity mappings in key-value store.
	// this needs to be done *after* init() for the daemon in that function,
	// we populate the IPCache with the host's IP(s).
	ipcache.InitIPIdentityWatcher()

	// FIXME: Make the port range configurable.
	d.l7Proxy = proxy.StartProxySupport(10000, 20000, option.Config.RunDir,
		option.Config.AccessLog, &d, option.Config.AgentLabels)

	if option.Config.RestoreState {
		d.regenerateRestoredEndpoints(restoredEndpoints)

		go func() {
			if err := d.SyncLBMap(); err != nil {
				log.WithError(err).Warn("Error while recovering endpoints")
			}
		}()
	} else {
		log.Info("No previous state to restore. Cilium will not manage existing containers")
		// We need to read all docker containers so we know we won't
		// going to allocate the same IP addresses and we will ignore
		// these containers from reading.
		workloads.IgnoreRunningWorkloads()
	}

	d.collectStaleMapGarbage()

	// Allocate health endpoint IPs after restoring state
	log.Info("Building health endpoint")
	health4, health6, err := ipam.AllocateNext("")
	if err != nil {
		log.WithError(err).Fatal("Error while allocating cilium-health IP")
	}
	node.SetIPv4HealthIP(health4)
	node.SetIPv6HealthIP(health6)
	log.Debugf("IPv4 health endpoint address: %s", node.GetIPv4HealthIP())
	log.Debugf("IPv6 health endpoint address: %s", node.GetIPv6HealthIP())

	d.startStatusCollector()
	d.dnsPoller = fqdn.NewDNSPoller(fqdn.DNSPollerConfig{
		LookupDNSNames: fqdn.DNSLookupDefaultResolver,
		AddGeneratedRules: func(generatedRules []*policyApi.Rule) error {
			// Insert the new rules into the policy repository. We need them to
			// replace the previous set. This requires the labels to match (including
			// the ToFQDN-UUID one).
			_, err := d.PolicyAdd(generatedRules, &AddOptions{Replace: true})
			return err
		}})
	fqdn.StartDNSPoller(d.dnsPoller)

	return &d, nil
}

func (d *Daemon) validateExistingMaps() error {
	walker := func(path string, _ os.FileInfo, _ error) error {
		return mapValidateWalker(path)
	}

	return filepath.Walk(bpf.MapPrefixPath(), walker)
}

func (d *Daemon) collectStaleMapGarbage() {
	if d.DryModeEnabled() {
		return
	}
	walker := func(path string, _ os.FileInfo, _ error) error {
		return d.staleMapWalker(path)
	}

	if err := filepath.Walk(bpf.MapPrefixPath(), walker); err != nil {
		log.WithError(err).Warn("Error while scanning for stale maps")
	}
}

func (d *Daemon) removeStaleMap(path string) {
	if err := os.RemoveAll(path); err != nil {
		log.WithError(err).WithField(logfields.Path, path).Warn("Error while deleting stale map file")
	} else {
		log.WithField(logfields.Path, path).Info("Removed stale bpf map")
	}
}

func (d *Daemon) removeStaleIDFromPolicyMap(id uint32) {
	gpm, err := policymap.OpenGlobalMap(bpf.MapPath(endpoint.PolicyGlobalMapName))
	if err == nil {
		gpm.Delete(id, policymap.AllPorts, u8proto.All, policymap.Ingress)
		gpm.Delete(id, policymap.AllPorts, u8proto.All, policymap.Egress)
		gpm.Close()
	}
}

func (d *Daemon) checkStaleMap(path string, filename string, id string) {
	if tmp, err := strconv.ParseUint(id, 0, 16); err == nil {
		if ep := endpointmanager.LookupCiliumID(uint16(tmp)); ep == nil {
			d.removeStaleIDFromPolicyMap(uint32(tmp))
			d.removeStaleMap(path)
		}
	}
}

func (d *Daemon) checkStaleGlobalMap(path string, filename string) {
	globalCTinUse := endpointmanager.HasGlobalCT()

	if !globalCTinUse &&
		(filename == ctmap.MapName6Global ||
			filename == ctmap.MapName4Global) {
		d.removeStaleMap(path)
	}
}

func (d *Daemon) staleMapWalker(path string) error {
	filename := filepath.Base(path)

	mapPrefix := []string{
		policymap.MapName,
		ctmap.MapName6,
		ctmap.MapName4,
		endpoint.CallsMapName,
	}

	d.checkStaleGlobalMap(path, filename)

	for _, m := range mapPrefix {
		if strings.HasPrefix(filename, m) {
			if id := strings.TrimPrefix(filename, m); id != filename {
				d.checkStaleMap(path, filename, id)
			}
		}
	}

	return nil
}

func mapValidateWalker(path string) error {
	prefixToValidator := map[string]bpf.MapValidator{
		policymap.MapName: policymap.Validate,
	}

	filename := filepath.Base(path)
	for m, validate := range prefixToValidator {
		if strings.HasPrefix(filename, m) {
			valid, err := validate(path)
			switch {
			case err != nil:
				return err
			case !valid:
				log.WithField(logfields.Path, filename).Info("Outdated non-persistent BPF map found, removing...")

				if err := os.Remove(path); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func changedOption(key string, value int, data interface{}) {
	d := data.(*Daemon)
	if key == option.Debug {
		// Set the debug toggle (this can be a no-op)
		logging.ToggleDebugLogs(d.DebugEnabled())
		// Reflect log level change to proxies
		proxy.ChangeLogLevel(log.Level)
	}
	d.policy.BumpRevision() // force policy recalculation
}

type patchConfig struct {
	daemon *Daemon
}

func NewPatchConfigHandler(d *Daemon) PatchConfigHandler {
	return &patchConfig{daemon: d}
}

func (h *patchConfig) Handle(params PatchConfigParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("PATCH /config request")

	d := h.daemon

	// Serialize configuration updates to the daemon.
	option.Config.ConfigPatchMutex.Lock()
	defer option.Config.ConfigPatchMutex.Unlock()

	cfgSpec := params.Configuration
	nmArgs := d.nodeMonitor.GetArgs()
	if numPagesEntry, ok := cfgSpec.Options["MonitorNumPages"]; ok && nmArgs[0] != numPagesEntry {
		if len(nmArgs) == 0 || nmArgs[0] != numPagesEntry {
			args := []string{"--num-pages %s", numPagesEntry}
			d.nodeMonitor.Restart(args)
		}
		if len(cfgSpec.Options) == 0 {
			return NewPatchConfigOK()
		}
		delete(cfgSpec.Options, "MonitorNumPages")
	}
	if err := option.Config.Opts.Validate(cfgSpec.Options); err != nil {
		return api.Error(PatchConfigBadRequestCode, err)
	}

	// Track changes to daemon's configuration
	var changes int

	// Only update if value provided for PolicyEnforcement.
	if enforcement := cfgSpec.PolicyEnforcement; enforcement != "" {
		switch enforcement {
		case option.NeverEnforce, option.DefaultEnforcement, option.AlwaysEnforce:
			// Update policy enforcement configuration if needed.
			oldEnforcementValue := policy.GetPolicyEnabled()

			// If the policy enforcement configuration has indeed changed, we have
			// to regenerate endpoints and update daemon's configuration.
			if enforcement != oldEnforcementValue {
				log.Debug("configuration request to change PolicyEnforcement for daemon")
				changes++
				policy.SetPolicyEnabled(enforcement)
			}

		default:
			msg := fmt.Errorf("Invalid option for PolicyEnforcement %s", enforcement)
			log.Warn(msg)
			return api.Error(PatchConfigFailureCode, msg)
		}
		log.Debug("finished configuring PolicyEnforcement for daemon")
	}

	changes += option.Config.Opts.ApplyValidated(cfgSpec.Options, changedOption, d)

	log.WithField("count", changes).Debug("Applied changes to daemon's configuration")

	if changes > 0 {
		// Only recompile if configuration has changed.
		log.Debug("daemon configuration has changed; recompiling base programs")
		if err := d.compileBase(); err != nil {
			msg := fmt.Errorf("Unable to recompile base programs: %s", err)
			return api.Error(PatchConfigFailureCode, msg)
		}
		d.TriggerPolicyUpdates(true)
	}

	return NewPatchConfigOK()
}

func (d *Daemon) getNodeAddressing() *models.NodeAddressing {
	return node.GetNodeAddressing(!option.Config.IPv4Disabled)
}

type getConfig struct {
	daemon *Daemon
}

func NewGetConfigHandler(d *Daemon) GetConfigHandler {
	return &getConfig{daemon: d}
}

func (h *getConfig) Handle(params GetConfigParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /config request")

	d := h.daemon

	spec := &models.DaemonConfigurationSpec{
		Options:           *option.Config.Opts.GetMutableModel(),
		PolicyEnforcement: policy.GetPolicyEnabled(),
	}

	status := &models.DaemonConfigurationStatus{
		Addressing:       d.getNodeAddressing(),
		K8sConfiguration: k8s.GetKubeconfigPath(),
		K8sEndpoint:      k8s.GetAPIServer(),
		NodeMonitor:      d.nodeMonitor.State(),
		KvstoreConfiguration: &models.KVstoreConfiguration{
			Type:    kvStore,
			Options: kvStoreOpts,
		},
		Realized:  spec,
		DeviceMTU: int64(mtu.GetDeviceMTU()),
		RouteMTU:  int64(mtu.GetRouteMTU()),
	}

	cfg := &models.DaemonConfiguration{
		Spec:   spec,
		Status: status,
	}

	return NewGetConfigOK().WithPayload(cfg)
}

// listFilterIfs returns a map of interfaces based on the given filter.
// The filter should take a link and, if found, return the index of that
// interface, if not found return -1.
func listFilterIfs(filter func(netlink.Link) int) (map[int]netlink.Link, error) {
	ifs, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	vethLXCIdxs := map[int]netlink.Link{}
	for _, intf := range ifs {
		if idx := filter(intf); idx != -1 {
			vethLXCIdxs[idx] = intf
		}
	}
	return vethLXCIdxs, nil
}

// clearCiliumVeths checks all veths created by cilium and removes all that
// are considered a leftover from failed attempts to connect the container.
func (d *Daemon) clearCiliumVeths() error {

	leftVeths, err := listFilterIfs(func(intf netlink.Link) int {
		// Filter by veth and return the index of the interface.
		if intf.Type() == "veth" {
			return intf.Attrs().Index
		}
		return -1
	})

	if err != nil {
		return fmt.Errorf("unable to retrieve host network interfaces: %s", err)
	}

	for _, v := range leftVeths {
		peerIndex := v.Attrs().ParentIndex
		parentVeth, found := leftVeths[peerIndex]
		if found && peerIndex != 0 && strings.HasPrefix(parentVeth.Attrs().Name, "lxc") {
			err := netlink.LinkDel(v)
			if err != nil {
				fmt.Printf(`CleanVeths: Unable to delete leftover veth "%d %s": %s`,
					v.Attrs().Index, v.Attrs().Name, err)
			}
		}
	}
	return nil
}

// numWorkerThreads returns the number of worker threads with a minimum of 4.
func numWorkerThreads() int {
	ncpu := runtime.NumCPU()
	minWorkerThreads := 2

	if ncpu < minWorkerThreads {
		return minWorkerThreads
	}
	return ncpu
}

// GetServiceList returns list of services
func (d *Daemon) GetServiceList() []*models.Service {
	list := []*models.Service{}

	d.loadBalancer.BPFMapMU.RLock()
	defer d.loadBalancer.BPFMapMU.RUnlock()

	for _, v := range d.loadBalancer.SVCMap {
		list = append(list, v.GetModel())
	}
	return list
}

// SendNotification sends an agent notification to the monitor
func (d *Daemon) SendNotification(typ monitor.AgentNotification, text string) error {
	event := monitor.AgentNotify{Type: typ, Text: text}
	return d.nodeMonitor.SendEvent(monitor.MessageTypeAgent, event)
}

// NewProxyLogRecord is invoked by the proxy accesslog on each new access log entry
func (d *Daemon) NewProxyLogRecord(l *logger.LogRecord) error {
	return d.nodeMonitor.SendEvent(monitor.MessageTypeAccessLog, l.LogRecord)
}

// GetNodeSuffix returns the suffix to be appended to kvstore keys of this
// agent
func (d *Daemon) GetNodeSuffix() string {
	if ip := node.GetExternalIPv4(); ip != nil {
		return ip.String()
	}

	log.Fatal("Node IP not available yet")
	return "<nil>"
}
