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

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/gob"
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
	"github.com/cilium/cilium/daemon/defaults"
	"github.com/cilium/cilium/daemon/options"
	monitorLaunch "github.com/cilium/cilium/monitor/launch"
	"github.com/cilium/cilium/monitor/payload"
	"github.com/cilium/cilium/pkg/apierror"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/workloads"
	"github.com/cilium/cilium/pkg/workloads/containerd"

	"github.com/go-openapi/runtime/middleware"
	"github.com/mattn/go-shellwords"
	"github.com/sirupsen/logrus"
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
	initArgMax
)

// Daemon is the cilium daemon that is in charge of perform all necessary plumbing,
// monitoring when a LXC starts.
type Daemon struct {
	buildEndpointChan chan *endpoint.Request
	conf              *Config
	l7Proxy           *proxy.Proxy
	loadBalancer      *types.LoadBalancer
	loopbackIPv4      net.IP
	policy            *policy.Repository
	preFilter         *policy.PreFilter

	uniqueIDMU lock.Mutex
	uniqueID   map[uint64]bool

	nodeMonitor  monitorLaunch.NodeMonitor
	ciliumHealth *health.CiliumHealth

	// k8sAPIs is a set of k8s API in use. They are setup in EnableK8sWatcher,
	// and may be disabled while the agent runs.
	// This is on this object, instead of a global, because EnableK8sWatcher is
	// on Daemon.
	k8sAPIGroups k8sAPIGroupsUsed

	// Used to synchronize generation of daemon's BPF programs and endpoint BPF
	// programs.
	compilationMutex *lock.RWMutex
}

// UpdateProxyRedirect updates the redirect rules in the proxy for a particular
// endpoint using the provided L4 filter. Returns the allocated proxy port
func (d *Daemon) UpdateProxyRedirect(e *endpoint.Endpoint, l4 *policy.L4Filter) (uint16, error) {
	if d.l7Proxy == nil {
		return 0, fmt.Errorf("can't redirect, proxy disabled")
	}

	r, err := d.l7Proxy.CreateOrUpdateRedirect(l4, e.ProxyID(l4), e, d, e.ProxyWaitGroup)
	if err != nil {
		return 0, err
	}

	return r.ToPort(), nil
}

// RemoveProxyRedirect removes a previously installed proxy redirect for an
// endpoint
func (d *Daemon) RemoveProxyRedirect(e *endpoint.Endpoint, id string) error {
	if d.l7Proxy == nil {
		return nil
	}

	log.WithFields(logrus.Fields{
		logfields.EndpointID: e.ID,
		logfields.L4PolicyID: id,
	}).Debug("Removing redirect to endpoint")
	return d.l7Proxy.RemoveRedirect(id, e.ProxyWaitGroup)
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

// GetTunnelMode returns the path to the state directory
func (d *Daemon) GetTunnelMode() string {
	return d.conf.Tunnel
}

// GetStateDir returns the path to the state directory
func (d *Daemon) GetStateDir() string {
	return d.conf.StateDir
}

func (d *Daemon) GetBpfDir() string {
	return d.conf.BpfDir
}

// GetPolicyRepository returns the policy repository of the daemon
func (d *Daemon) GetPolicyRepository() *policy.Repository {
	return d.policy
}

func (d *Daemon) TracingEnabled() bool {
	return d.conf.Opts.IsEnabled(options.PolicyTracing)
}

func (d *Daemon) DryModeEnabled() bool {
	return d.conf.DryMode
}

// AlwaysAllowLocalhost returns true if the daemon has the option set that
// localhost can always reach local endpoints
func (d *Daemon) AlwaysAllowLocalhost() bool {
	return d.conf.alwaysAllowLocalhost
}

// PolicyEnforcement returns the type of policy enforcement for the daemon.
func (d *Daemon) PolicyEnforcement() string {
	return policy.GetPolicyEnabled()
}

// DebugEnabled returns if debug mode is enabled.
func (d *Daemon) DebugEnabled() bool {
	return d.conf.Opts.IsEnabled(endpoint.OptionDebug)
}

// ResetProxyPort cleans the connection tracking of the given endpoint
// where the given endpoint IPs and the idsToRm match the CT entry fields.
// isCTLocal should be set as true if the endpoint's CT table is either
// local or not (if it is not local then it is assumed to be global).
// Implementation of pkg/endpoint.Owner interface
func (d *Daemon) ResetProxyPort(e *endpoint.Endpoint, isCTLocal bool, ips []net.IP, idsToMod policy.SecurityIDContexts) {
	endpointmanager.ResetProxyPort(!d.conf.IPv4Disabled, e, isCTLocal, ips, idsToMod)
}

// FlushCTEntries flushes the connection tracking of the given endpoint
// where the given endpoint IPs match the CT entry fields.
// isCTLocal should be set as true if the endpoint's CT table is either
// local or not (if it is not local then it is assumed to be global).
// Implementation of pkg/endpoint.Owner interface
func (d *Daemon) FlushCTEntries(e *endpoint.Endpoint, isCTLocal bool, ips []net.IP, idsToKeep policy.SecurityIDContexts) {
	endpointmanager.FlushCTEntriesOf(!d.conf.IPv4Disabled, e, isCTLocal, ips, idsToKeep)
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
	fw.WriteString(d.conf.Opts.GetFmtList())
	fw.WriteString(d.fmtPolicyEnforcementIngress())
	fw.WriteString(d.fmtPolicyEnforcementEgress())

	return fw.Flush()
}

// returns #define for PolicyIngress based on the configuration of the daemon.
func (d *Daemon) fmtPolicyEnforcementIngress() string {
	if policy.GetPolicyEnabled() == endpoint.AlwaysEnforce {
		return fmt.Sprintf("#define %s\n", endpoint.OptionIngressSpecPolicy.Define)
	}
	return fmt.Sprintf("#undef %s\n", endpoint.OptionIngressSpecPolicy.Define)
}

// returns #define for PolicyEgress based on the configuration of the daemon.
func (d *Daemon) fmtPolicyEnforcementEgress() string {
	if policy.GetPolicyEnabled() == endpoint.AlwaysEnforce {
		return fmt.Sprintf("#define %s\n", endpoint.OptionEgressSpecPolicy.Define)
	}
	return fmt.Sprintf("#undef %s\n", endpoint.OptionEgressSpecPolicy.Define)
}

// Must be called with d.conf.EnablePolicyMU locked.
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
	fmt.Fprintf(fw, " * XDP device: %s\n", d.conf.DevicePreFilter)
	fmt.Fprintf(fw, " * XDP mode: %s\n", d.conf.ModePreFilter)
	fmt.Fprint(fw, " */\n\n")
	d.preFilter.WriteConfig(fw)
	return fw.Flush()
}

func (d *Daemon) setHostAddresses() error {
	l, err := netlink.LinkByName(d.conf.LBInterface)
	if err != nil {
		return fmt.Errorf("unable to get network device %s: %s", d.conf.Device, err)
	}

	getAddr := func(netLinkFamily int) (net.IP, error) {
		addrs, err := netlink.AddrList(l, netLinkFamily)
		if err != nil {
			return nil, fmt.Errorf("error while getting %s's addresses: %s", d.conf.Device, err)
		}
		for _, possibleAddr := range addrs {
			if netlink.Scope(possibleAddr.Scope) == netlink.SCOPE_UNIVERSE {
				return possibleAddr.IP, nil
			}
		}
		return nil, nil
	}

	if !d.conf.IPv4Disabled {
		hostV4Addr, err := getAddr(netlink.FAMILY_V4)
		if err != nil {
			return err
		}
		if hostV4Addr != nil {
			d.conf.HostV4Addr = hostV4Addr
			log.Infof("Using IPv4 host address: %s", d.conf.HostV4Addr)
		}
	}
	hostV6Addr, err := getAddr(netlink.FAMILY_V6)
	if err != nil {
		return err
	}
	if hostV6Addr != nil {
		d.conf.HostV6Addr = hostV6Addr
		log.Infof("Using IPv6 host address: %s", d.conf.HostV6Addr)
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
	if err := runProg("iptables", []string{
		"-t", "mangle",
		"-A", ciliumPostMangleChain,
		"-o", "cilium_host",
		"-m", "comment", "--comment", "cilium: clear masq bit for pkts to cilium_host",
		"-j", "MARK", "--set-xmark", "0x0000/0x4000"}, false); err != nil {
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

	if masquerade {
		// Masquerade all traffic from the host into the cilium_host interface
		// if the source is not the internal IP
		if err := runProg("iptables", []string{
			"-t", "nat",
			"-A", ciliumPostNatChain,
			"!", "-s", node.GetHostMasqueradeIPv4().String(),
			"-o", "cilium_host",
			"-m", "comment", "--comment", "cilium host->cluster masquerade",
			"-j", "SNAT", "--to-source", node.GetHostMasqueradeIPv4().String()}, false); err != nil {
			return err
		}

		// Masquerade all traffic from node prefix not going to node prefix
		// which is not going over the tunnel device
		if err := runProg("iptables", []string{
			"-t", "nat",
			"-A", "CILIUM_POST",
			"-s", node.GetIPv4AllocRange().String(),
			"!", "-d", node.GetIPv4AllocRange().String(),
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

	scopedLog := log.WithField(logfields.XDPDevice, d.conf.DevicePreFilter)
	if d.conf.DevicePreFilter != "undefined" {
		if err := policy.ProbePreFilter(d.conf.DevicePreFilter, d.conf.ModePreFilter); err != nil {
			scopedLog.WithError(err).Warn("Turning off prefilter")
			d.conf.DevicePreFilter = "undefined"
		}
	}
	if d.conf.DevicePreFilter != "undefined" {
		if d.preFilter, ret = policy.NewPreFilter(); ret != nil {
			scopedLog.WithError(ret).Warn("Unable to init prefilter")
			return ret
		}

		if err := d.writePreFilterHeader("./"); err != nil {
			scopedLog.WithError(err).Warn("Unable to write prefilter header")
			return err
		}

		args[initArgDevicePreFilter] = d.conf.DevicePreFilter
		args[initArgModePreFilter] = d.conf.ModePreFilter
	}

	args[initArgLib] = d.conf.BpfDir
	args[initArgRundir] = d.conf.StateDir
	args[initArgIPv4NodeIP] = node.GetInternalIPv4().String()
	args[initArgIPv6NodeIP] = node.GetIPv6().String()

	if d.conf.Device != "undefined" {
		_, err := netlink.LinkByName(d.conf.Device)
		if err != nil {
			log.WithError(err).WithField("device", d.conf.Device).Warn("Link does not exist")
			return err
		}

		if d.conf.IsLBEnabled() {
			if d.conf.Device != d.conf.LBInterface {
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
		args[initArgDevice] = d.conf.Device

		args = append(args, d.conf.Device)
	} else {
		if d.conf.IsLBEnabled() {
			//FIXME: allow LBMode in tunnel
			return fmt.Errorf("Unable to run LB mode with tunnel mode")
		}

		args[initArgMode] = d.conf.Tunnel
	}

	prog := filepath.Join(d.conf.BpfDir, "init.sh")
	ctx, cancel := context.WithTimeout(context.Background(), ExecTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, prog, args...).CombinedOutput()
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

	if !d.conf.IPv4Disabled {
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
	globalsDir := filepath.Join(d.conf.StateDir, "globals")
	if err := os.MkdirAll(globalsDir, defaults.RuntimePathRights); err != nil {
		log.WithError(err).WithField(logfields.Path, globalsDir).Fatal("Could not create runtime directory")
	}

	if err := os.Chdir(d.conf.StateDir); err != nil {
		log.WithError(err).WithField(logfields.Path, d.conf.StateDir).Fatal("Could not change to runtime directory")
	}

	nodeConfigPath := "./globals/node_config.h"
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

	if d.conf.IPv4Disabled {
		fw.WriteString(" */\n\n")
	} else {
		fmt.Fprintf(fw, ""+
			" * Host-IPv4: %s\n"+
			" */\n\n"+
			"#define ENABLE_IPV4\n",
			node.GetInternalIPv4().String())
	}

	fw.WriteString(common.FmtDefineComma("ROUTER_IP", routerIP))

	if !d.conf.IPv4Disabled {
		ipv4GW := node.GetInternalIPv4()
		fmt.Fprintf(fw, "#define IPV4_GATEWAY %#x\n", byteorder.HostSliceToNetwork(ipv4GW, reflect.Uint32).(uint32))
		fmt.Fprintf(fw, "#define IPV4_LOOPBACK %#x\n", byteorder.HostSliceToNetwork(d.loopbackIPv4, reflect.Uint32).(uint32))
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

	if nat46Range := d.conf.NAT46Prefix; nat46Range != nil {
		fw.WriteString(common.FmtDefineAddress("NAT46_PREFIX", nat46Range.IP))
	}

	fw.WriteString(common.FmtDefineComma("HOST_IP", hostIP))
	fmt.Fprintf(fw, "#define HOST_ID %d\n", policy.GetReservedID(labels.IDNameHost))
	fmt.Fprintf(fw, "#define WORLD_ID %d\n", policy.GetReservedID(labels.IDNameWorld))
	fmt.Fprintf(fw, "#define CLUSTER_ID %d\n", policy.GetReservedID(labels.IDNameCluster))
	fmt.Fprintf(fw, "#define LB_RR_MAX_SEQ %d\n", lbmap.MaxSeq)

	fmt.Fprintf(fw, "#define TUNNEL_ENDPOINT_MAP_SIZE %d\n", tunnel.MaxEntries)
	fmt.Fprintf(fw, "#define ENDPOINTS_MAP_SIZE %d\n", lxcmap.MaxKeys)

	fmt.Fprintf(fw, "#define TRACE_PAYLOAD_LEN %dULL\n", tracePayloadLen)

	fw.Flush()
	f.Close()

	if !d.DryModeEnabled() {
		// Validate existing map paths before attempting BPF compile.
		if err = d.validateExistingMaps(); err != nil {
			log.WithError(err).Error("Error while validating maps")
			return err
		}

		if err := d.compileBase(); err != nil {
			return err
		}

		localIPs := []net.IP{
			node.GetInternalIPv4(),
			node.GetExternalIPv4(),
			node.GetIPv6(),
			node.GetIPv6Router(),
		}
		for _, ip := range localIPs {
			log.WithField(logfields.IPAddr, ip).Debug("Adding local ip to endpoint map")
			if err := lxcmap.AddHostEntry(ip); err != nil {
				return fmt.Errorf("Unable to add host entry to endpoint map: %s", err)
			}
		}

		if _, err := lbmap.Service6Map.OpenOrCreate(); err != nil {
			return err
		}
		if _, err := lbmap.RevNat6Map.OpenOrCreate(); err != nil {
			return err
		}
		if _, err := lbmap.RRSeq6Map.OpenOrCreate(); err != nil {
			return err
		}
		if !d.conf.IPv4Disabled {
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
		if !d.conf.RestoreState {
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

			if !d.conf.IPv4Disabled {
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

// NewDaemon creates and returns a new Daemon with the parameters set in c.
func NewDaemon(c *Config) (*Daemon, error) {
	if c == nil {
		return nil, fmt.Errorf("Configuration is nil")
	}

	if opts := workloads.GetRuntimeOpt(workloads.Docker); opts != nil {
		if err := containerd.Init(dockerEndpoint); err != nil {
			return nil, err
		}
	}

	lb := types.NewLoadBalancer()

	d := Daemon{
		conf:         c,
		loadBalancer: lb,
		policy:       policy.NewPolicyRepository(),
		uniqueID:     map[uint64]bool{},

		// FIXME
		// The channel size has to be set to the maximum number of
		// possible endpoints to guarantee that enqueueing into the
		// build queue never blocks.
		buildEndpointChan: make(chan *endpoint.Request, lxcmap.MaxKeys),
		compilationMutex:  new(lock.RWMutex),
	}

	workloads.Init(&d)

	// Clear previous leftovers before listening for new requests
	err := d.clearCiliumVeths()
	if err != nil {
		log.WithError(err).Debug("Unable to clean leftover veths")
	}

	// Create at least 4 worker threads or the same amount as there are
	// CPUs.
	d.StartEndpointBuilders(numWorkerThreads())

	if k8s.IsEnabled() {
		if err := k8s.Init(); err != nil {
			log.WithError(err).Fatal("Unable to initialize Kubernetes subsystem")
		}

		// Kubernetes demands that the localhost can always reach local
		// pods. Therefore unless the AllowLocalhost policy is set to a
		// specific mode, always allow localhost to reach local
		// endpoints.
		if d.conf.AllowLocalhost == AllowLocalhostAuto {
			log.Info("k8s mode: Allowing localhost to reach local endpoints")
			config.alwaysAllowLocalhost = true
		}

		if !singleClusterRoute {
			node.EnablePerNodeRoutes()
		}
	}
	// If the device has been specified, the IPv4AllocPrefix and the
	// IPv6AllocPrefix were already allocated before the k8s.Init().
	//
	// If the device hasn't been specified, k8s.Init() allocated the
	// IPv4AllocPrefix and the IPv6AllocPrefix from k8s node annotations.
	//
	// Then, we will calculate the IPv4 or IPv6 alloc prefix based on the IPv6
	// or IPv4 alloc prefix, respectively, retrieved by k8s node annotations.
	if config.Device == "undefined" {
		node.InitDefaultPrefix("")
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

	if err := node.AutoComplete(); err != nil {
		log.WithError(err).Fatal("Cannot autocomplete node IPv6 address")
	}

	if k8s.IsEnabled() {
		err := k8s.AnnotateNode(k8s.Client(), node.GetName(),
			node.GetIPv4AllocRange(), node.GetIPv6NodeRange(),
			nil, nil)
		if err != nil {
			log.WithError(err).Warning("Cannot annotate k8s node with CIDR range")
		}
	}

	// Set up ipam conf after init() because we might be running d.conf.KVStoreIPv4Registration
	if err = ipam.Init(); err != nil {
		log.WithError(err).Fatal("IPAM init failed")
	}

	if err := node.ValidatePostInit(); err != nil {
		log.WithError(err).Fatal("postinit failed")
	}
	// REVIEW should these be changed? they seem intended for humans
	log.Info("Addressing information:")
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

	// Populate list of nodes with local node entry
	ni, n := node.GetLocalNode()
	node.UpdateNode(ni, n, node.TunnelRoute, nil)

	// This needs to be done after the node addressing has been configured
	// as the node address is required as sufix
	policy.InitIdentityAllocator(&d)

	if !d.conf.IPv4Disabled {
		// Allocate IPv4 service loopback IP
		loopbackIPv4, _, err := ipam.AllocateNext("ipv4")
		if err != nil {
			return nil, fmt.Errorf("Unable to reserve IPv4 loopback address: %s", err)
		}
		d.loopbackIPv4 = loopbackIPv4
		log.Infof("Loopback IPv4: %s", d.loopbackIPv4.String())
	}

	if err = d.init(); err != nil {
		log.WithError(err).Error("Error while initializing daemon")
		return nil, err
	}

	// FIXME: Make configurable
	d.l7Proxy = proxy.NewProxy(10000, 20000)

	if c.RestoreState {
		if err := d.SyncState(d.conf.StateDir, true); err != nil {
			log.WithError(err).Warn("Error while recovering endpoints")
		}
		if err := d.SyncLBMap(); err != nil {
			log.WithError(err).Warn("Error while recovering endpoints")
		}
	} else {
		// We need to read all docker containers so we know we won't
		// going to allocate the same IP addresses and we will ignore
		// these containers from reading.
		containerd.IgnoreRunningContainers()
	}

	d.collectStaleMapGarbage()

	// Allocate health endpoint IPs after restoring state
	health4, health6, err := ipam.AllocateNext("")
	if err != nil {
		log.WithError(err).Fatal("Error while allocating cilium-health IP")
	}
	node.SetIPv4HealthIP(health4)
	node.SetIPv6HealthIP(health6)
	log.Debugf("IPv4 health endpoint address: %s", node.GetIPv4HealthIP())
	log.Debugf("IPv6 health endpoint address: %s", node.GetIPv6HealthIP())

	return &d, nil
}

func (d *Daemon) validateExistingMaps() error {
	walker := func(path string, _ os.FileInfo, _ error) error {
		return mapValidateWalker(path)
	}

	return filepath.Walk(bpf.MapPrefixPath(), walker)
}

func (d *Daemon) collectStaleMapGarbage() {
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
		gpm.DeleteIdentity(id)
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

func changedOption(key string, value bool, data interface{}) {
	d := data.(*Daemon)
	if key == endpoint.OptionDebug {
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
	d.conf.ConfigPatchMutex.Lock()
	defer d.conf.ConfigPatchMutex.Unlock()

	if numPagesEntry, ok := params.Configuration.Mutable["MonitorNumPages"]; ok {
		nmArgs := d.nodeMonitor.GetArgs()
		if len(nmArgs) == 0 || nmArgs[0] != numPagesEntry {
			args := []string{"--num-pages %s", numPagesEntry}
			d.nodeMonitor.Restart(args)
		}
		if len(params.Configuration.Mutable) == 0 {
			return NewPatchConfigOK()
		}
		delete(params.Configuration.Mutable, "MonitorNumPages")
	}
	if err := d.conf.Opts.Validate(params.Configuration.Mutable); err != nil {
		return apierror.Error(PatchConfigBadRequestCode, err)
	}

	// Track changes to daemon's configuration
	var changes int

	enforcement := params.Configuration.PolicyEnforcement

	// Only update if value provided for PolicyEnforcement.
	if enforcement != "" {
		log.Debug("configuration request to change PolicyEnforcement for daemon")
		switch enforcement {
		case endpoint.NeverEnforce, endpoint.DefaultEnforcement, endpoint.AlwaysEnforce:

			// Update policy enforcement configuration if needed.
			oldEnforcementValue := policy.GetPolicyEnabled()

			// If the policy enforcement configuration has indeed changed, we have
			// to regenerate endpoints and update daemon's configuration.
			if enforcement != oldEnforcementValue {
				changes++
				policy.SetPolicyEnabled(enforcement)
				d.TriggerPolicyUpdates(true)
			}
		default:
			msg := fmt.Errorf("Invalid option for PolicyEnforcement %s", enforcement)
			log.Warn(msg)
			return apierror.Error(PatchConfigFailureCode, msg)
		}
		log.Debug("finished configuring PolicyEnforcement for daemon")
	}

	changes += d.conf.Opts.Apply(params.Configuration.Mutable, changedOption, d)

	log.WithField("count", changes).Debug("Applied changes to daemon's configuration")

	if changes > 0 {
		// Only recompile if configuration has changed.
		log.Debug("daemon configuration has changed; recompiling base programs")
		if err := d.compileBase(); err != nil {
			log.WithError(err).Warn("Invalid option for PolicyEnforcement")
			msg := fmt.Errorf("Unable to recompile base programs: %s", err)
			return apierror.Error(PatchConfigFailureCode, msg)
		}
	}

	return NewPatchConfigOK()
}

func (d *Daemon) getNodeAddressing() *models.NodeAddressing {
	return node.GetNodeAddressing(!d.conf.IPv4Disabled)
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

	cfg := &models.DaemonConfigurationResponse{
		Addressing:        d.getNodeAddressing(),
		Configuration:     d.conf.Opts.GetModel(),
		K8sConfiguration:  k8s.GetKubeconfigPath(),
		K8sEndpoint:       k8s.GetAPIServer(),
		PolicyEnforcement: policy.GetPolicyEnabled(),
		NodeMonitor:       d.nodeMonitor.State(),
		KvstoreConfiguration: &models.KVstoreConfiguration{
			Type:    kvStore,
			Options: kvStoreOpts,
		},
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
	minWorkerThreads := 4

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

func (d *Daemon) SendNotification(typ monitor.AgentNotification, text string) error {
	var (
		buf   bytes.Buffer
		event = monitor.AgentNotify{Type: typ, Text: text}
	)

	if err := gob.NewEncoder(&buf).Encode(event); err != nil {
		return fmt.Errorf("Unable to gob encode: %s", err)
	}

	err := d.sendEvent(append([]byte{byte(monitor.MessageTypeAgent)}, buf.Bytes()...))
	if err != nil {
		log.WithError(err).Debug("Failed to send agent notification")
	}

	return err
}

// NewProxyLogRecord is invoked by the proxy accesslog on each new access log entry
func (d *Daemon) NewProxyLogRecord(l *accesslog.LogRecord) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(l); err != nil {
		return fmt.Errorf("Unable to gob encode: %s", err)
	}

	return d.sendEvent(append([]byte{byte(monitor.MessageTypeAccessLog)}, buf.Bytes()...))
}

func (d *Daemon) sendEvent(data []byte) error {
	d.nodeMonitor.PipeLock.Lock()
	defer d.nodeMonitor.PipeLock.Unlock()

	if d.nodeMonitor.Pipe == nil {
		return fmt.Errorf("monitor pipe not opened")
	}

	p := payload.Payload{Data: data, CPU: 0, Lost: 0, Type: payload.EventSample}

	payloadBuf, err := p.Encode()
	if err != nil {
		return fmt.Errorf("Unable to encode payload: %s", err)
	}

	meta := &payload.Meta{Size: uint32(len(payloadBuf))}
	metaBuf, err := meta.MarshalBinary()
	if err != nil {
		return fmt.Errorf("Unable to encode metadata: %s", err)
	}

	if _, err := d.nodeMonitor.Pipe.Write(metaBuf); err != nil {
		d.nodeMonitor.Pipe.Close()
		d.nodeMonitor.Pipe = nil
		return fmt.Errorf("Unable to write metadata: %s", err)
	}

	if _, err := d.nodeMonitor.Pipe.Write(payloadBuf); err != nil {
		d.nodeMonitor.Pipe.Close()
		d.nodeMonitor.Pipe = nil
		return fmt.Errorf("Unable to write payload: %s", err)
	}

	return nil
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
