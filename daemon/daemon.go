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
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/ipam"
	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/daemon/defaults"
	"github.com/cilium/cilium/daemon/options"
	monitor "github.com/cilium/cilium/monitor/launch"
	"github.com/cilium/cilium/pkg/apierror"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/container"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/events"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/nodeaddress"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy"

	log "github.com/Sirupsen/logrus"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	hb "github.com/containernetworking/cni/plugins/ipam/host-local/backend/allocator"
	dClient "github.com/docker/engine-api/client"
	"github.com/go-openapi/runtime/middleware"
	"github.com/mattn/go-shellwords"
	"github.com/vishvananda/netlink"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/pkg/registry/core/service/ipallocator"
)

const (
	// ExecTimeout is the execution timeout to use in init.sh executions
	ExecTimeout = time.Duration(30 * time.Second)

	// AutoCIDR indicates that a CIDR should be allocated
	AutoCIDR = "auto"
)

const (
	initArgLib int = iota
	initArgRundir
	initArgIPv6Router
	initArgIPv4NodeIP
	initArgIPv6NodeIP
	initArgIPv4Range
	initArgIPv6Range
	initArgIPv4ServiceRange
	initArgIPv6ServiceRange
	initArgMode
	initArgDevice
	initArgMax
)

// Daemon is the cilium daemon that is in charge of perform all necessary plumbing,
// monitoring when a LXC starts.
type Daemon struct {
	buildEndpointChan chan *endpoint.Request
	conf              *Config
	consumableCache   *policy.ConsumableCache
	dockerClient      *dClient.Client
	events            chan events.Event
	ipamConf          *ipam.IPAMConfig
	k8sClient         kubernetes.Interface
	l7Proxy           *proxy.Proxy
	loadBalancer      *types.LoadBalancer
	loopbackIPv4      net.IP
	policy            *policy.Repository

	containersMU sync.RWMutex
	containers   map[string]*container.Container

	ignoredMutex      sync.RWMutex
	ignoredContainers map[string]int

	maxCachedLabelIDMU sync.RWMutex
	maxCachedLabelID   policy.NumericIdentity

	uniqueIDMU sync.Mutex
	uniqueID   map[uint64]bool

	nodeMonitor *monitor.NodeMonitor

	// Used to synchronize generation of daemon's BPF programs and endpoint BPF
	// programs.
	compilationMutex *sync.RWMutex
}

// UpdateProxyRedirect updates the redirect rules in the proxy for a particular
// endpoint using the provided L4 filter. Returns the allocated proxy port
func (d *Daemon) UpdateProxyRedirect(e *endpoint.Endpoint, l4 *policy.L4Filter) (uint16, error) {
	if d.l7Proxy == nil {
		return 0, fmt.Errorf("can't redirect, proxy disabled")
	}

	log.Debugf("Adding redirect %+v to endpoint %d", l4, e.ID)
	r, err := d.l7Proxy.CreateOrUpdateRedirect(l4, e.ProxyID(l4), e)
	if err != nil {
		return 0, err
	}

	return r.ToPort, nil
}

// RemoveProxyRedirect removes a previously installed proxy redirect for an
// endpoint
func (d *Daemon) RemoveProxyRedirect(e *endpoint.Endpoint, l4 *policy.L4Filter) error {
	if d.l7Proxy == nil {
		return nil
	}

	id := e.ProxyID(l4)
	log.Debugf("Removing redirect %s from endpoint %d", id, e.ID)
	return d.l7Proxy.RemoveRedirect(id)
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
	log.Debugf("Creating %d worker threads", nRoutines)
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
	return d.conf.StateDir
}

func (d *Daemon) GetBpfDir() string {
	return d.conf.BpfDir
}

// GetPolicyRepository returns the policy repository of the daemon
func (d *Daemon) GetPolicyRepository() *policy.Repository {
	return d.policy
}

func (d *Daemon) GetConsumableCache() *policy.ConsumableCache {
	return d.consumableCache
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
func (d *Daemon) PolicyEnforcement() (pe string) {
	d.conf.EnablePolicyMU.RLock()
	pe = d.conf.EnablePolicy
	d.conf.EnablePolicyMU.RUnlock()
	return
}

// DebugEnabled returns if debug mode is enabled.
func (d *Daemon) DebugEnabled() bool {
	return d.conf.Opts.IsEnabled(endpoint.OptionDebug)
}

// AnnotateEndpoint adds a Kubernetes annotation with key annotationKey and value
// annotationValue if Kubernetes is being utilized in tandem with Cilium.
func (d *Daemon) AnnotateEndpoint(e *endpoint.Endpoint, annotationKey, annotationValue string) {

	if !d.conf.IsK8sEnabled() {
		return // Don't error out if k8s is not enabled; treat as a no-op.
	}

	go func(e *endpoint.Endpoint) {
		// TODO: Retry forever?
		n := 0
		for {
			// Endpoint's PodName is in the format namespace:pod-name
			split := strings.Split(e.PodName, ":")

			if len(split) < 2 {
				log.Errorf("k8s: unable to update pod %s with annotation %q: namespace and pod name should be delimited by %q", e.PodName, common.CiliumIdentityAnnotation, ":")
				return
			}

			pod, err := d.k8sClient.CoreV1().Pods(split[0]).Get(split[1], meta_v1.GetOptions{})
			if err != nil {
				log.Errorf("error getting pod for endpoint %d with namespace %s and pod name %s: %s", e.ID, split[0], split[1], err)
				return
			}

			if pod.Annotations == nil {
				pod.Annotations = make(map[string]string)
			}
			pod.Annotations[annotationKey] = annotationValue
			pod, err = d.k8sClient.CoreV1().Pods(split[0]).Update(pod)
			if err == nil {
				log.Debugf("added %s annotation to endpoint %d / pod %s:%s", common.CiliumIdentityAnnotation, e.ID, split[0], split[1])
				break
			}
			log.Warningf("k8s: unable to update  endpoint %d / pod %s:%s with %q annotation: %s, retrying...", e.ID, split[0], split[1], common.CiliumIdentityAnnotation, err)
			if n < 30 {
				n++
			}
			time.Sleep(time.Duration(n) * time.Second)
		}
	}(e)
}

func createDockerClient(endpoint string) (*dClient.Client, error) {
	defaultHeaders := map[string]string{"User-Agent": "cilium"}
	return dClient.NewClient(endpoint, "v1.21", nil, defaultHeaders)
}

// Must be called with d.conf.EnablePolicyMU locked.
func (d *Daemon) writeNetdevHeader(dir string) error {

	headerPath := filepath.Join(dir, common.NetdevHeaderFileName)

	log.Debugf("writing configuration to %s", headerPath)

	f, err := os.Create(headerPath)
	if err != nil {
		return fmt.Errorf("failed to open file %s for writing: %s", headerPath, err)

	}
	defer f.Close()

	fw := bufio.NewWriter(f)
	fw.WriteString(d.conf.Opts.GetFmtList())
	fw.WriteString(d.fmtPolicyEnforcement())

	return fw.Flush()
}

// returns #define for PolicyEnforcement based on the configuration of the daemon.
// Must be called with d.conf.EnablePolicyMU locked.
func (d *Daemon) fmtPolicyEnforcement() string {
	d.GetPolicyRepository().Mutex.RLock()
	enforcement := d.EnablePolicyEnforcement()
	d.GetPolicyRepository().Mutex.RUnlock()

	if enforcement {
		return fmt.Sprintf("#define %s\n", endpoint.OptionSpecPolicy.Define)
	}
	return fmt.Sprintf("#undef %s\n", endpoint.OptionSpecPolicy.Define)
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
		log.Errorf("Command execution failed: Timeout for %s %s", prog, args)
		return fmt.Errorf("Command execution failed: Timeout for %s %s", prog, args)
	}
	if err != nil {
		if !quiet {
			log.Warningf("Command execution %s %s failed: %s", prog,
				strings.Join(args, " "), err)

			scanner := bufio.NewScanner(bytes.NewReader(out))
			for scanner.Scan() {
				log.Warning(scanner.Text())
			}
		}
	}

	return err
}

func nextIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func reserveLocalRoutes(ipam *ipam.IPAMConfig) {
	log.Debugf("Checking local routes for conflicts...")

	link, err := netlink.LinkByName("cilium_host")
	if err != nil || link == nil {
		log.Warningf("Unable to find net_device cilium_host: %s", err)
		return
	}

	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		log.Warningf("Unable to retrieve local routes: %s", err)
		return
	}

	allocRange := nodeaddress.GetIPv4AllocRange()

	for _, r := range routes {
		// ignore routes which point to cilium_host
		if r.LinkIndex == link.Attrs().Index {
			log.Debugf("Ignoring route %v: points to cilium_host", r)
			continue
		}

		if r.Dst == nil {
			log.Debugf("Ignoring route %v: no destination address", r)
			continue
		}

		log.Debugf("Considering route %v", r)

		if allocRange.Contains(r.Dst.IP) {
			log.Infof("Marking local route %s as no-alloc in node allocation prefix %s", r.Dst, allocRange)
			for ip := r.Dst.IP.Mask(r.Dst.Mask); r.Dst.Contains(ip); nextIP(ip) {
				ipam.IPv4Allocator.Allocate(ip)
			}
		}
	}
}

const (
	ciliumPostNatChain = "CILIUM_POST"
	feederDescription  = "cilium-feeder:"
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
		log.WithError(err).Fatalf("Unable to parse rule '%s' into argument slice", args)
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
		log.Errorf("Command execution failed: Timeout for %s %s", prog, args)
		return
	}
	if err != nil {
		log.Warningf("Command execution %s %s failed: %s", prog,
			strings.Join(args, " "), err)
		return
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		rule := scanner.Text()
		log.Debugf("Considering to remove iptables rule '%s'", rule)
		if strings.Contains(strings.ToLower(rule), "cilium") &&
			(strings.HasPrefix(rule, "-A") || strings.HasPrefix(rule, "-I")) {
			// From: -A POSTROUTING -m comment [...]
			// To:   -D POSTROUTING -m comment [...]
			ruleAsArgs, err := shellwords.Parse(strings.Replace(rule, "-A", "-D", 1))
			if err != nil {
				log.WithError(err).Warningf("Unable to parse iptables rule '%s' into slice. Leaving rule behind.")
				continue
			}

			deleteRule := append([]string{"-t", table}, ruleAsArgs...)
			log.Debugf("Removing iptables rule '%v'", deleteRule)
			err = runProg("iptables", deleteRule, true)
			if err != nil {
				log.WithError(err).Warningf("Unable to delete Cilium iptables rule '%s'", rule)
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
}

func (d *Daemon) removeMasqRule() {
	tables := []string{"nat", "mangle", "raw"}
	for _, t := range tables {
		removeCiliumRules(t)
	}

	for _, c := range ciliumChains {
		c.remove()
	}
}

func (d *Daemon) installMasqRule() error {
	for _, c := range ciliumChains {
		if err := c.add(); err != nil {
			return fmt.Errorf("cannot add custom chain %s: %s", c.name, err)
		}
	}

	// Masquerade all traffic from node prefix not going to node prefix
	// which is not going over the tunnel device
	if err := runProg("iptables", []string{
		"-t", "nat",
		"-A", "CILIUM_POST",
		"-s", nodeaddress.GetIPv4AllocRange().String(),
		"!", "-d", nodeaddress.GetIPv4AllocRange().String(),
		"!", "-o", "cilium_" + d.conf.Tunnel,
		"-m", "comment", "--comment", "cilium masquerade non-cluster",
		"-j", "MASQUERADE"}, false); err != nil {
		return err
	}

	// Masquerade all traffic from the host into the cilium_host interface
	// if the source is not the internal IP
	if err := runProg("iptables", []string{
		"-t", "nat",
		"-A", ciliumPostNatChain,
		"!", "-s", nodeaddress.GetInternalIPv4().String(),
		"-o", "cilium_host",
		"-m", "comment", "--comment", "cilium host->cluster masquerade",
		"-j", "MASQUERADE"}, false); err != nil {
		return err
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
func (d *Daemon) GetCompilationLock() *sync.RWMutex {
	return d.compilationMutex
}

// Must be called with d.conf.EnablePolicyMU locked.
func (d *Daemon) compileBase() error {
	var args []string
	var mode string

	// Lock so that endpoints cannot be built while we are compile base programs.
	d.compilationMutex.Lock()
	defer d.compilationMutex.Unlock()

	if err := d.writeNetdevHeader("./"); err != nil {
		log.Warningf("Unable to write netdev header: %s", err)
		return err
	}

	args = make([]string, initArgMax)

	args[initArgLib] = d.conf.BpfDir
	args[initArgRundir] = d.conf.StateDir
	args[initArgIPv6Router] = nodeaddress.GetIPv6NoZeroComp()
	args[initArgIPv4NodeIP] = nodeaddress.GetInternalIPv4().String()
	args[initArgIPv6NodeIP] = nodeaddress.GetIPv6().String()
	args[initArgIPv4ServiceRange] = v4ServicePrefix
	args[initArgIPv6ServiceRange] = v6ServicePrefix

	if d.conf.Device != "undefined" {
		_, err := netlink.LinkByName(d.conf.Device)
		if err != nil {
			log.Warningf("Link %s does not exist: %s", d.conf.Device, err)
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

		// in direct routing mode, only packets to the local node
		// prefix should go to cilium_host
		args[initArgIPv4Range] = nodeaddress.GetIPv4AllocRange().String()
		args[initArgIPv6Range] = nodeaddress.GetIPv6NodeRange().String()

		args[initArgMode] = mode
		args[initArgDevice] = d.conf.Device

		args = append(args, d.conf.Device)
	} else {
		if d.conf.IsLBEnabled() {
			//FIXME: allow LBMode in tunnel
			return fmt.Errorf("Unable to run LB mode with tunnel mode")
		}

		// in tunnel mode, all packets in the cluster should go to cilium_host
		args[initArgIPv4Range] = nodeaddress.GetIPv4ClusterRange().String()
		args[initArgIPv6Range] = nodeaddress.GetIPv6ClusterRange().String()

		args[initArgMode] = d.conf.Tunnel
	}

	prog := filepath.Join(d.conf.BpfDir, "init.sh")
	ctx, cancel := context.WithTimeout(context.Background(), ExecTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, prog, args...).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		log.Errorf("Command execution failed: Timeout for %s %s", prog, args)
		return fmt.Errorf("Command execution failed: Timeout for %s %s", prog, args)
	}
	if err != nil {
		log.Warningf("Command execution %s %s failed: %s", prog,
			strings.Join(args, " "), err)

		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			log.Warning(scanner.Text())
		}
		return err
	}

	reserveLocalRoutes(d.ipamConf)

	if !d.conf.IPv4Disabled {
		// Always remove masquerade rule and then re-add it if required
		d.removeMasqRule()
		if masquerade {
			if err := d.installMasqRule(); err != nil {
				return err
			}
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
		log.Fatalf("Could not create runtime directory %s: %s", globalsDir, err)
	}

	if err := os.Chdir(d.conf.StateDir); err != nil {
		log.Fatalf("Could not change to runtime directory %s: \"%s\"",
			d.conf.StateDir, err)
	}

	f, err := os.Create("./globals/node_config.h")
	if err != nil {
		log.Warningf("Failed to create node configuration file: %s", err)
		return err

	}
	fw := bufio.NewWriter(f)

	routerIP := nodeaddress.GetIPv6Router()
	hostIP := nodeaddress.GetIPv6()

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
			nodeaddress.GetInternalIPv4().String())
	}

	fw.WriteString(common.FmtDefineComma("ROUTER_IP", routerIP))

	if !d.conf.IPv4Disabled {
		ipv4GW := nodeaddress.GetInternalIPv4()
		fmt.Fprintf(fw, "#define IPV4_GATEWAY %#x\n", byteorder.HostSliceToNetwork(ipv4GW, reflect.Uint32).(uint32))
		fmt.Fprintf(fw, "#define IPV4_LOOPBACK %#x\n", byteorder.HostSliceToNetwork(d.loopbackIPv4, reflect.Uint32).(uint32))
	} else {
		// FIXME: Workaround so the bpf program compiles
		fmt.Fprintf(fw, "#define IPV4_GATEWAY %#x\n", 0)
		fmt.Fprintf(fw, "#define IPV4_LOOPBACK %#x\n", 0)
	}

	ipv4Range := nodeaddress.GetIPv4AllocRange()
	fmt.Fprintf(fw, "#define IPV4_MASK %#x\n", byteorder.HostSliceToNetwork(ipv4Range.Mask, reflect.Uint32).(uint32))

	ipv4ClusterRange := nodeaddress.GetIPv4ClusterRange()
	fmt.Fprintf(fw, "#define IPV4_CLUSTER_RANGE %#x\n", byteorder.HostSliceToNetwork(ipv4ClusterRange.IP, reflect.Uint32).(uint32))
	fmt.Fprintf(fw, "#define IPV4_CLUSTER_MASK %#x\n", byteorder.HostSliceToNetwork(ipv4ClusterRange.Mask, reflect.Uint32).(uint32))

	if nat46Range := d.conf.NAT46Prefix; nat46Range != nil {
		fw.WriteString(common.FmtDefineAddress("NAT46_PREFIX", nat46Range.IP))
	}

	fw.WriteString(common.FmtDefineComma("HOST_IP", hostIP))
	fmt.Fprintf(fw, "#define HOST_ID %d\n", policy.GetReservedID(labels.IDNameHost))
	fmt.Fprintf(fw, "#define WORLD_ID %d\n", policy.GetReservedID(labels.IDNameWorld))
	fmt.Fprintf(fw, "#define LB_RR_MAX_SEQ %d\n", lbmap.MaxSeq)

	fmt.Fprintf(fw, "#define TUNNEL_ENDPOINT_MAP_SIZE %d\n", tunnel.MaxEntries)
	fmt.Fprintf(fw, "#define ENDPOINTS_MAP_SIZE %d\n", lxcmap.MaxKeys)

	fmt.Fprintf(fw, "#define TRACE_PAYLOAD_LEN %dULL\n", tracePayloadLen)

	fw.Flush()
	f.Close()

	if !d.DryModeEnabled() {
		d.conf.EnablePolicyMU.Lock()
		if err := d.compileBase(); err != nil {
			d.conf.EnablePolicyMU.Unlock()
			return err
		}

		d.conf.EnablePolicyMU.Unlock()

		localIPs := []net.IP{
			nodeaddress.GetInternalIPv4(),
			nodeaddress.GetExternalIPv4(),
			nodeaddress.GetIPv6(),
			nodeaddress.GetIPv6Router(),
		}
		for _, ip := range localIPs {
			log.Debugf("Adding %v as local ip to endpoint map", ip)
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
			log.Debugf("cleaning up all BPF LB maps")

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

func (c *Config) createIPAMConf() (*ipam.IPAMConfig, error) {

	ipamSubnets := net.IPNet{
		IP:   nodeaddress.GetIPv6Router(),
		Mask: nodeaddress.StateIPv6Mask,
	}

	ipamConf := &ipam.IPAMConfig{
		IPAMConfig: hb.IPAMConfig{
			Name:    "cilium-local-IPAM",
			Subnet:  cniTypes.IPNet(ipamSubnets),
			Gateway: nodeaddress.GetIPv6Router(),
			Routes: []cniTypes.Route{
				// IPv6
				{
					Dst: nodeaddress.GetIPv6NodeRoute(),
				},
				{
					Dst: nodeaddress.IPv6DefaultRoute,
					GW:  nodeaddress.GetIPv6Router(),
				},
			},
		},
		IPv6Allocator: ipallocator.NewCIDRRange(nodeaddress.GetIPv6AllocRange()),
	}

	// Since docker doesn't support IPv6 only and there's always an IPv4
	// address we can set up ipam for IPv4. More info:
	// https://github.com/docker/libnetwork/pull/826
	ipamConf.IPv4Allocator = ipallocator.NewCIDRRange(nodeaddress.GetIPv4AllocRange())
	ipamConf.IPAMConfig.Routes = append(ipamConf.IPAMConfig.Routes,
		// IPv4
		cniTypes.Route{
			Dst: nodeaddress.GetIPv4NodeRoute(),
		},
		cniTypes.Route{
			Dst: nodeaddress.IPv4DefaultRoute,
			GW:  nodeaddress.GetInternalIPv4(),
		})

	// Reserve the IPv4 router IP if it is part of the IPv4
	// allocation range to ensure that we do not hand out the
	// router IP to a container.
	allocRange := nodeaddress.GetIPv4AllocRange()
	nodeIP := nodeaddress.GetExternalIPv4()
	if allocRange.Contains(nodeIP) {
		err := ipamConf.IPv4Allocator.Allocate(nodeIP)
		if err != nil {
			log.Debugf("Unable to reserve IPv4 router address '%s': %s",
				nodeIP, err)
		}
	}

	internalIP, err := ipamConf.IPv4Allocator.AllocateNext()
	if err != nil {
		log.Fatalf("Unable to allocate internal IPv4 node IP: %s", err)
	}

	nodeaddress.SetInternalIPv4(internalIP)

	// Reserve the IPv6 router and node IP if it is part of the IPv6
	// allocation range to ensure that we do not hand out the router IP to
	// a container.
	allocRange = nodeaddress.GetIPv6AllocRange()
	for _, ip6 := range []net.IP{nodeaddress.GetIPv6()} {
		if allocRange.Contains(ip6) {
			err := ipamConf.IPv6Allocator.Allocate(ip6)
			if err != nil {
				log.Debugf("Unable to reserve IPv6 address '%s': %s",
					ip6, err)
			}
		}
	}

	routerIP, err := ipamConf.IPv6Allocator.AllocateNext()
	if err != nil {
		log.Fatalf("Unable to allocate IPv6 router IP: %s", err)
	}

	nodeaddress.SetIPv6Router(routerIP)

	return ipamConf, nil
}

// NewDaemon creates and returns a new Daemon with the parameters set in c.
func NewDaemon(c *Config) (*Daemon, error) {
	if c == nil {
		return nil, fmt.Errorf("Configuration is nil")
	}

	dockerClient, err := createDockerClient(c.DockerEndpoint)
	if err != nil {
		return nil, err
	}

	lb := types.NewLoadBalancer()

	d := Daemon{
		conf:              c,
		dockerClient:      dockerClient,
		containers:        make(map[string]*container.Container),
		events:            make(chan events.Event, 512),
		loadBalancer:      lb,
		consumableCache:   policy.NewConsumableCache(),
		policy:            policy.NewPolicyRepository(),
		ignoredContainers: make(map[string]int),
		uniqueID:          map[uint64]bool{},

		// FIXME
		// The channel size has to be set to the maximum number of
		// possible endpoints to guarantee that enqueueing into the
		// build queue never blocks.
		buildEndpointChan: make(chan *endpoint.Request, lxcmap.MaxKeys),
		compilationMutex:  new(sync.RWMutex),
	}

	// Clear previous leftovers before listening for new requests
	err = d.clearCiliumVeths()
	if err != nil {
		log.Debugf("Unable to clean leftover veths: %s", err)
	}

	// Create at least 4 worker threads or the same amount as there are
	// CPUs.
	d.StartEndpointBuilders(numWorkerThreads())

	d.listenForCiliumEvents()

	if c.IsK8sEnabled() {
		restConfig, err := k8s.CreateConfig(c.K8sEndpoint, c.K8sCfgPath)
		if err != nil {
			return nil, fmt.Errorf("unable to create rest configuration: %s", err)
		}

		d.k8sClient, err = k8s.CreateClient(restConfig)
		if err != nil {
			return nil, fmt.Errorf("unable to create k8s client: %s", err)
		}

		if nodeName := os.Getenv(k8s.EnvNodeNameSpec); nodeName != "" {
			// Use of the environment variable overwrites the
			// node-name automatically derived
			nodeaddress.SetName(nodeName)

			k8sNode, err := k8s.GetNode(d.k8sClient, nodeName)
			if err != nil {
				return nil, fmt.Errorf("unable to retrieve k8s node information: %s", err)
			}

			node := k8s.ParseNode(k8sNode)

			log.Infof("Retrieved node's %s information from kubernetes", node.Name)

			if err := nodeaddress.UseNodeCIDR(node); err != nil {
				return nil, fmt.Errorf("unable to retrieve k8s node CIDR: %s", err)
			}

			if err := nodeaddress.UseNodeAddresses(node); err != nil {
				return nil, fmt.Errorf("unable to use k8s node addresses: %s", err)
			}

			// Annotate addresses will occur later since the user might want
			// to specify them manually

		}

		// Kubernetes demands that the localhost can always reach local
		// pods. Therefore unless the AllowLocalhost policy is set to a
		// specific mode, always allow localhost to reach local
		// endpoints.
		if d.conf.AllowLocalhost == AllowLocalhostAuto {
			log.Infof("k8s mode: Allowing localhost to reach local endpoints")
			config.alwaysAllowLocalhost = true
		}
	}

	nodeaddress.SetIPv4ClusterCidrMaskSize(v4ClusterCidrMaskSize)

	if v4Prefix != AutoCIDR {
		_, net, err := net.ParseCIDR(v4Prefix)
		if err != nil {
			log.Fatalf("Invalid IPv4 allocation prefix '%s': %s", v4Prefix, err)
		}
		nodeaddress.SetIPv4AllocRange(net)
	}

	if v4ServicePrefix != AutoCIDR {
		_, _, err := net.ParseCIDR(v4ServicePrefix)
		if err != nil {
			log.Fatalf("Invalid IPv4 service prefix '%s': %s", v4ServicePrefix, err)
		}
	}

	if v6Prefix != AutoCIDR {
		_, net, err := net.ParseCIDR(v6Prefix)
		if err != nil {
			log.Fatalf("Invalid IPv6 allocation prefix '%s': %s", v6Prefix, err)
		}

		if err := nodeaddress.SetIPv6NodeRange(net); err != nil {
			log.Fatalf("Invalid per node IPv6 allocation prefix '%s': %s", net, err)
		}
	}

	if v6ServicePrefix != AutoCIDR {
		_, _, err := net.ParseCIDR(v6ServicePrefix)
		if err != nil {
			log.Fatalf("Invalid IPv6 service prefix '%s': %s", v6ServicePrefix, err)
		}
	}

	if err := nodeaddress.AutoComplete(); err != nil {
		log.Fatalf("%s", err)
	}

	// Populate list of nodes with local node entry
	node.UpdateNode(nodeaddress.GetNode())

	if c.IsK8sEnabled() {
		err := k8s.AnnotateNodeCIDR(d.k8sClient, nodeaddress.GetName(),
			nodeaddress.GetIPv4AllocRange(),
			nodeaddress.GetIPv6NodeRange())
		if err != nil {
			log.Fatalf("Unable to get k8s node: %s", err)
		}
	}

	// Set up ipam conf after init() because we might be running d.conf.KVStoreIPv4Registration
	if d.ipamConf, err = d.conf.createIPAMConf(); err != nil {
		return nil, err
	}

	if err := nodeaddress.ValidatePostInit(); err != nil {
		log.Fatalf("%s", err)
	}

	log.Infof("Local node-name: %s", nodeaddress.GetName())
	log.Infof("Node-IPv6: %s", nodeaddress.GetIPv6())
	log.Infof("External-Node IPv4: %s", nodeaddress.GetExternalIPv4())
	log.Infof("Internal-Node IPv4: %s", nodeaddress.GetInternalIPv4())
	log.Infof("Cluster IPv6 prefix: %s", nodeaddress.GetIPv6ClusterRange())
	log.Infof("Cluster IPv4 prefix: %s", nodeaddress.GetIPv4ClusterRange())
	log.Infof("IPv6 node prefix: %s", nodeaddress.GetIPv6NodeRange())
	log.Infof("IPv6 allocation prefix: %s", nodeaddress.GetIPv6AllocRange())
	log.Infof("IPv4 allocation prefix: %s", nodeaddress.GetIPv4AllocRange())
	log.Debugf("IPv6 router address: %s", nodeaddress.GetIPv6Router())

	if !d.conf.IPv4Disabled {
		// Allocate IPv4 service loopback IP
		loopbackIPv4, err := d.ipamConf.IPv4Allocator.AllocateNext()
		if err != nil {
			return nil, fmt.Errorf("Unable to reserve IPv4 loopback address: %s", err)
		}
		d.loopbackIPv4 = loopbackIPv4
	}

	if err = d.init(); err != nil {
		log.Errorf("Error while initializing daemon: %s", err)
		return nil, err
	}

	// FIXME: Make configurable
	d.l7Proxy = proxy.NewProxy(10000, 20000)

	if c.RestoreState {
		if err := d.SyncState(d.conf.StateDir, true); err != nil {
			log.Warningf("Error while recovering endpoints: %s", err)
		}
		if err := d.SyncLBMap(); err != nil {
			log.Warningf("Error while recovering endpoints: %s", err)
		}
	} else {
		// We need to read all docker containers so we know we won't
		// going to allocate the same IP addresses and we will ignore
		// these containers from reading.
		d.IgnoreRunningContainers()
	}

	d.collectStaleMapGarbage()

	return &d, nil
}

func (d *Daemon) collectStaleMapGarbage() {
	endpointmanager.Mutex.RLock()
	defer endpointmanager.Mutex.RUnlock()

	walker := func(path string, _ os.FileInfo, _ error) error {
		return d.staleMapWalker(path)
	}

	if err := filepath.Walk(bpf.MapPrefixPath(), walker); err != nil {
		log.Warningf("Error while scanning for stale maps: %s", err)
	}
}

func (d *Daemon) removeStaleMap(path string) {
	if err := os.RemoveAll(path); err != nil {
		log.Warningf("Error while deleting stale map file %s: %s", path, err)
	} else {
		log.Infof("Removed stale bpf map %s", path)
	}
}

func (d *Daemon) removeStaleIDFromPolicyMap(id uint32) {
	gpm, err := policymap.OpenGlobalMap(bpf.MapPath(endpoint.PolicyGlobalMapName))
	if err == nil {
		gpm.DeleteConsumer(id)
		gpm.Close()
	}
}

// call with endpointmanager.Mutex.RLocked
func (d *Daemon) checkStaleMap(path string, filename string, id string) {
	if tmp, err := strconv.ParseUint(id, 0, 16); err == nil {
		if _, ok := endpointmanager.Endpoints[uint16(tmp)]; !ok {
			d.removeStaleIDFromPolicyMap(uint32(tmp))
			d.removeStaleMap(path)
		}
	}
}

// call with endpointmanager.Mutex.RLocked
func (d *Daemon) checkStaleGlobalMap(path string, filename string) {
	var globalCTinUse = false

	for k := range endpointmanager.Endpoints {
		e := endpointmanager.Endpoints[k]
		if e.Consumable != nil &&
			e.Opts.IsDisabled(endpoint.OptionConntrackLocal) {
			globalCTinUse = true
			break
		}
	}

	if !globalCTinUse &&
		(filename == ctmap.MapName6Global ||
			filename == ctmap.MapName4Global) {
		d.removeStaleMap(path)
	}
}

// call with endpointmanager.Mutex.RLocked
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

func changedOption(key string, value bool, data interface{}) {
}

type patchConfig struct {
	daemon *Daemon
}

func NewPatchConfigHandler(d *Daemon) PatchConfigHandler {
	return &patchConfig{daemon: d}
}

func (h *patchConfig) Handle(params PatchConfigParams) middleware.Responder {
	log.Debugf("PATCH /config request: %+v", params)

	d := h.daemon

	// Serialize configuration updates to the daemon.
	d.conf.ConfigPatchMutex.Lock()
	defer d.conf.ConfigPatchMutex.Unlock()

	if numPagesEntry, ok := params.Configuration.Mutable["MonitorNumPages"]; ok {
		if d.nodeMonitor.Arg != numPagesEntry {
			d.nodeMonitor.Restart(numPagesEntry)
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
		log.Debugf("configuration request to change PolicyEnforcement for daemon")
		switch enforcement {
		case endpoint.NeverEnforce, endpoint.DefaultEnforcement, endpoint.AlwaysEnforce:

			// Update policy enforcement configuration if needed.
			config.EnablePolicyMU.Lock()
			oldEnforcementValue := config.EnablePolicy

			// If the policy enforcement configuration has indeed changed, we have
			// to regenerate endpoints and update daemon's configuration.
			if enforcement != oldEnforcementValue {
				changes++
				config.EnablePolicy = enforcement
				d.TriggerPolicyUpdates([]policy.NumericIdentity{})
			}
			config.EnablePolicyMU.Unlock()
		default:
			msg := fmt.Errorf("Invalid option for PolicyEnforcement %s", enforcement)
			log.Warningf("%s", msg)
			return apierror.Error(PatchConfigFailureCode, msg)
		}
		log.Debugf("finished configuring PolicyEnforcement for daemon")
	}

	changes += d.conf.Opts.Apply(params.Configuration.Mutable, changedOption, d)

	log.Debugf("Applied %d changes to daemon's configuration", changes)

	// Only recompile if configuration has changed.
	if changes > 0 {
		log.Debugf("daemon configuration has changed; recompiling base programs")
		d.conf.EnablePolicyMU.Lock()
		defer d.conf.EnablePolicyMU.Unlock()
		if err := d.compileBase(); err != nil {
			msg := fmt.Errorf("Unable to recompile base programs: %s", err)
			log.Warningf("%s", msg)
			return apierror.Error(PatchConfigFailureCode, msg)
		}
	}

	return NewPatchConfigOK()
}

func (d *Daemon) getNodeAddressing() *models.NodeAddressing {
	return &models.NodeAddressing{
		IPV6: &models.NodeAddressingElement{
			Enabled:    true,
			IP:         nodeaddress.GetIPv6Router().String(),
			AllocRange: nodeaddress.GetIPv6AllocRange().String(),
		},
		IPV4: &models.NodeAddressingElement{
			Enabled:    !d.conf.IPv4Disabled,
			IP:         nodeaddress.GetInternalIPv4().String(),
			AllocRange: nodeaddress.GetIPv4AllocRange().String(),
		},
	}
}

type getConfig struct {
	daemon *Daemon
}

func NewGetConfigHandler(d *Daemon) GetConfigHandler {
	return &getConfig{daemon: d}
}

func (h *getConfig) Handle(params GetConfigParams) middleware.Responder {
	log.Debugf("GET /config request: %+v", params)

	d := h.daemon

	cfg := &models.DaemonConfigurationResponse{
		Addressing:        d.getNodeAddressing(),
		Configuration:     d.conf.Opts.GetModel(),
		K8sConfiguration:  d.conf.K8sCfgPath,
		K8sEndpoint:       d.conf.K8sEndpoint,
		PolicyEnforcement: d.conf.EnablePolicy,
		NodeMonitor:       d.nodeMonitor.State(),
	}

	return NewGetConfigOK().WithPayload(cfg)
}

func (d *Daemon) IgnoredContainer(id string) bool {
	d.ignoredMutex.RLock()
	_, ok := d.ignoredContainers[id]
	d.ignoredMutex.RUnlock()

	return ok
}

func (d *Daemon) StartIgnoringContainer(id string) {
	d.ignoredMutex.Lock()
	d.ignoredContainers[id]++
	d.ignoredMutex.Unlock()
}

func (d *Daemon) StopIgnoringContainer(id string) {
	d.ignoredMutex.Lock()
	delete(d.ignoredContainers, id)
	d.ignoredMutex.Unlock()
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
