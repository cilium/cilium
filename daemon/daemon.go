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

package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	health "github.com/cilium/cilium/cilium-health/launch"
	"github.com/cilium/cilium/common"
	monitorLaunch "github.com/cilium/cilium/monitor/launch"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cgroups"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/alignchecker"
	bpfIPCache "github.com/cilium/cilium/pkg/datapath/ipcache"
	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/datapath/prefilter"
	"github.com/cilium/cilium/pkg/debug"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/connector"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/eppolicymap"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	"github.com/cilium/cilium/pkg/maps/sockmap"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	nodemanager "github.com/cilium/cilium/pkg/node/manager"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	policyApi "github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/proxy/logger"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/sockops"
	"github.com/cilium/cilium/pkg/status"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/cilium/cilium/pkg/workloads"

	"github.com/go-openapi/runtime/middleware"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"
)

const (
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
	initArgIPSec
	initArgMasquerade
	initArgEncryptInterface
	initArgHostReachableServices
	initArgCgroupRoot
	initArgBpffsRoot
	initArgMax
)

// Daemon is the cilium daemon that is in charge of perform all necessary plumbing,
// monitoring when a LXC starts.
type Daemon struct {
	buildEndpointSem *semaphore.Weighted
	l7Proxy          *proxy.Proxy
	loadBalancer     *loadbalancer.LoadBalancer
	policy           *policy.Repository
	preFilter        *prefilter.PreFilter
	// Only used for CRI-O since it does not support events.
	workloadsEventsCh chan<- *workloads.EventMessage

	statusCollectMutex lock.RWMutex
	statusResponse     models.StatusResponse
	statusCollector    *status.Collector

	uniqueIDMU lock.Mutex
	uniqueID   map[uint64]context.CancelFunc

	nodeMonitor  *monitorLaunch.NodeMonitor
	ciliumHealth *health.CiliumHealth

	// dnsRuleGen manages toFQDNs rules
	dnsRuleGen *fqdn.RuleGen

	// dnsPoller polls DNS names and sends them to dnsRuleGen
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

	// k8sResourceSyncedMu protects the k8sResourceSynced map.
	k8sResourceSyncedMu lock.RWMutex

	// k8sResourceSynced maps a resource name to a channel. Once the given
	// resource name is synchronized with k8s, the channel for which that
	// resource name maps to is closed.
	k8sResourceSynced map[string]chan struct{}

	// k8sSvcCache is a cache of all Kubernetes services and endpoints
	k8sSvcCache k8s.ServiceCache

	mtuConfig     mtu.Configuration
	policyTrigger *trigger.Trigger

	// datapath is the underlying datapath implementation to use to
	// implement all aspects of an agent
	datapath datapath.Datapath

	// nodeDiscovery defines the node discovery logic of the agent
	nodeDiscovery *nodediscovery.NodeDiscovery

	// ipam is the IP address manager of the agent
	ipam *ipam.IPAM
}

// Datapath returns a reference to the datapath implementation.
func (d *Daemon) Datapath() datapath.Datapath {
	return d.datapath
}

// UpdateProxyRedirect updates the redirect rules in the proxy for a particular
// endpoint using the provided L4 filter. Returns the allocated proxy port
func (d *Daemon) UpdateProxyRedirect(e *endpoint.Endpoint, l4 *policy.L4Filter, proxyWaitGroup *completion.WaitGroup) (uint16, error, revert.FinalizeFunc, revert.RevertFunc) {
	if d.l7Proxy == nil {
		return 0, fmt.Errorf("can't redirect, proxy disabled"), nil, nil
	}

	port, err, finalizeFunc, revertFunc := d.l7Proxy.CreateOrUpdateRedirect(l4, e.ProxyID(l4), e, proxyWaitGroup)
	if err != nil {
		return 0, err, nil, nil
	}

	return port, nil, finalizeFunc, revertFunc
}

// RemoveProxyRedirect removes a previously installed proxy redirect for an
// endpoint
func (d *Daemon) RemoveProxyRedirect(e *endpoint.Endpoint, id string, proxyWaitGroup *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc) {
	if d.l7Proxy == nil {
		return nil, nil, nil
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
	labelsMap cache.IdentityCache, proxyWaitGroup *completion.WaitGroup) (error, revert.RevertFunc) {
	if d.l7Proxy == nil {
		return fmt.Errorf("can't update network policy, proxy disabled"), nil
	}
	err, revertFunc := d.l7Proxy.UpdateNetworkPolicy(e, policy, e.GetIngressPolicyEnabledLocked(),
		e.GetEgressPolicyEnabledLocked(), labelsMap, proxyWaitGroup)
	return err, revert.RevertFunc(revertFunc)
}

// RemoveNetworkPolicy removes a network policy from the set published to
// L7 proxies.
func (d *Daemon) RemoveNetworkPolicy(e *endpoint.Endpoint) {
	if d.l7Proxy == nil {
		return
	}
	d.l7Proxy.RemoveNetworkPolicy(e)
}

// QueueEndpointBuild waits for a "build permit" for the endpoint
// identified by 'epID'. This function blocks until the endpoint can
// start building.  The returned function must then be called to
// release the "build permit" when the most resource intensive parts
// of the build are done. The returned function is idempotent, so it
// may be called more than once. Returns a nil function if the caller should NOT
// start building the endpoint. This may happen due to a build being
// queued for the endpoint already, or due to the wait for the build
// permit being canceled. The latter case happens when the endpoint is
// being deleted. Returns an error if the build permit could not be acquired.
func (d *Daemon) QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error) {
	d.uniqueIDMU.Lock()
	// Skip new build requests if the endpoint is already in the queue
	// waiting. In this case the queued build will pick up any changes
	// made so far, so there is no need to queue another build now.
	if _, queued := d.uniqueID[epID]; queued {
		d.uniqueIDMU.Unlock()
		return nil, nil
	}
	// Store a cancel function to the 'uniqueID' map so that we can
	// cancel the wait when the endpoint is being deleted.
	uniqueIDCtx, cancel := context.WithCancel(ctx)
	d.uniqueID[epID] = cancel
	d.uniqueIDMU.Unlock()

	// Acquire build permit. This may block.
	err := d.buildEndpointSem.Acquire(uniqueIDCtx, 1)

	// Not queueing any more, so remove the cancel func from 'uniqueID' map.
	// The caller may still cancel the build by calling the cancel func after we
	// return it. After this point another build may be queued for this
	// endpoint.
	d.uniqueIDMU.Lock()
	delete(d.uniqueID, epID)
	d.uniqueIDMU.Unlock()

	if err != nil {
		return nil, err // Acquire failed
	}

	// Acquire succeeded, but the context was canceled after?
	if uniqueIDCtx.Err() != nil {
		d.buildEndpointSem.Release(1)
		return nil, uniqueIDCtx.Err()
	}

	// At this point the build permit has been acquired. It must
	// be released by the caller by calling the returned function
	// when the heavy lifting of the build is done.
	// Using sync.Once to make the returned function idempotent.
	var once sync.Once
	doneFunc := func() {
		once.Do(func() {
			d.buildEndpointSem.Release(1)
		})
	}
	return doneFunc, nil
}

// RemoveFromEndpointQueue removes the endpoint from the "build permit" queue,
// canceling the wait for the build permit if still waiting.
func (d *Daemon) RemoveFromEndpointQueue(epID uint64) {
	d.uniqueIDMU.Lock()
	if cancel, queued := d.uniqueID[epID]; queued && cancel != nil {
		delete(d.uniqueID, epID)
		cancel()
	}
	d.uniqueIDMU.Unlock()
}

// GetPolicyRepository returns the policy repository of the daemon
func (d *Daemon) GetPolicyRepository() *policy.Repository {
	return d.policy
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

	if err := d.datapath.WriteNetdevConfig(f, d); err != nil {
		return err
	}
	return nil
}

// GetCIDRPrefixLengths returns the sorted list of unique prefix lengths used
// by CIDR policies.
func (d *Daemon) GetCIDRPrefixLengths() (s6, s4 []int) {
	return d.prefixLengths.ToBPFData()
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

// GetOptions returns the datapath configuration options of the daemon.
func (d *Daemon) GetOptions() *option.IntOptions {
	return option.Config.Opts
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

	if option.Config.EnableIPv4 {
		hostV4Addr, err := getAddr(netlink.FAMILY_V4)
		if err != nil {
			return err
		}
		if hostV4Addr != nil {
			option.Config.HostV4Addr = hostV4Addr
			log.Infof("Using IPv4 host address: %s", option.Config.HostV4Addr)
		}
	}

	if option.Config.EnableIPv6 {
		hostV6Addr, err := getAddr(netlink.FAMILY_V6)
		if err != nil {
			return err
		}
		if hostV6Addr != nil {
			option.Config.HostV6Addr = hostV6Addr
			log.Infof("Using IPv6 host address: %s", option.Config.HostV6Addr)
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
	loader.Init(d.datapath, &d.nodeDiscovery.LocalConfig)

	scopedLog := log.WithField(logfields.XDPDevice, option.Config.DevicePreFilter)
	if option.Config.DevicePreFilter != "undefined" {
		if err := prefilter.ProbePreFilter(option.Config.DevicePreFilter, option.Config.ModePreFilter); err != nil {
			scopedLog.WithError(err).Warn("Turning off prefilter")
			option.Config.DevicePreFilter = "undefined"
		}
	}
	if option.Config.DevicePreFilter != "undefined" {
		if d.preFilter, ret = prefilter.NewPreFilter(); ret != nil {
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
	args[initArgCgroupRoot] = cgroups.GetCgroupRoot()
	args[initArgBpffsRoot] = bpf.GetMapRoot()

	if option.Config.EnableIPv4 {
		args[initArgIPv4NodeIP] = node.GetInternalIPv4().String()
	} else {
		args[initArgIPv4NodeIP] = "<nil>"
	}

	if option.Config.EnableIPv6 {
		args[initArgIPv6NodeIP] = node.GetIPv6().String()
	} else {
		args[initArgIPv6NodeIP] = "<nil>"
	}

	args[initArgMTU] = fmt.Sprintf("%d", d.mtuConfig.GetDeviceMTU())

	if option.Config.EnableIPSec {
		args[initArgIPSec] = "true"
	} else {
		args[initArgIPSec] = "false"
	}

	if !option.Config.InstallIptRules && option.Config.Masquerade {
		args[initArgMasquerade] = "true"
	} else {
		args[initArgMasquerade] = "false"
	}

	if option.Config.EnableHostReachableServices {
		args[initArgHostReachableServices] = "true"
	} else {
		args[initArgHostReachableServices] = "false"
	}

	if option.Config.EncryptInterface != "" {
		args[initArgEncryptInterface] = option.Config.EncryptInterface
	}

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
			if option.Config.DatapathMode == option.DatapathModeIpvlan {
				mode = "ipvlan"
			} else {
				mode = "direct"
			}
		}

		args[initArgMode] = mode
		args[initArgDevice] = option.Config.Device

		args = append(args, option.Config.Device)
	} else {
		if option.Config.IsLBEnabled() && strings.ToLower(option.Config.Tunnel) != "disabled" {
			//FIXME: allow LBMode in tunnel
			return fmt.Errorf("Unable to run LB mode with tunnel mode")
		}

		args[initArgMode] = option.Config.Tunnel

		if option.Config.IsFlannelMasterDeviceSet() {
			args[initArgMode] = "flannel"
			args[initArgDevice] = option.Config.FlannelMasterDevice
		}
	}

	prog := filepath.Join(option.Config.BpfDir, "init.sh")
	ctx, cancel := context.WithTimeout(context.Background(), defaults.ExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, prog, args...)
	cmd.Env = bpf.Environment()
	if _, err := cmd.CombinedOutput(log, true); err != nil {
		return err
	}

	if canDisableDwarfRelocations {
		// Validate alignments of C and Go equivalent structs
		if err := alignchecker.CheckStructAlignments(defaults.AlignCheckerName); err != nil {
			log.WithError(err).Fatal("C and Go structs alignment check failed")
		}
	} else {
		log.Warning("Cannot check matching of C and Go common struct alignments due to old LLVM/clang version")
	}

	if !option.Config.IsFlannelMasterDeviceSet() {
		d.ipam.ReserveLocalRoutes()
	}

	if err := d.datapath.Node().NodeConfigurationChanged(d.nodeDiscovery.LocalConfig); err != nil {
		return err
	}

	iptablesManager := iptables.IptablesManager{}
	iptablesManager.Init()
	// Always remove masquerade rule and then re-add it if required
	iptablesManager.RemoveRules()
	if option.Config.InstallIptRules {
		if err := iptablesManager.InstallRules(option.Config.HostDevice); err != nil {
			return err
		}
	}
	// Reinstall proxy rules for any running proxies
	if d.l7Proxy != nil {
		d.l7Proxy.ReinstallRules()
	}

	log.Info("Setting sysctl net.core.bpf_jit_enable=1")
	log.Info("Setting sysctl net.ipv4.conf.all.rp_filter=0")
	log.Info("Setting sysctl net.ipv6.conf.all.disable_ipv6=0")

	return nil
}

// initMaps opens all BPF maps (and creates them if they do not exist). This
// must be done *before* any operations which read BPF maps, especially
// restoring endpoints and services.
func (d *Daemon) initMaps() error {
	if option.Config.DryMode {
		return nil
	}

	if _, err := lxcmap.LXCMap.OpenOrCreate(); err != nil {
		return err
	}

	// The ipcache is shared between endpoints. Parallel mode needs to be
	// used to allow existing endpoints that have not been regenerated yet
	// to continue using the existing ipcache until the endpoint is
	// regenerated for the first time. Existing endpoints are using a
	// policy map which is potentially out of sync as local identities are
	// re-allocated on startup. Parallel mode allows to continue using the
	// old version until regeneration. Note that the old version is not
	// updated with new identities. This is fine as any new identity
	// appearing would require a regeneration of the endpoint anyway in
	// order for the endpoint to gain the privilege of communication.
	if _, err := ipcachemap.IPCache.OpenParallel(); err != nil {
		return err
	}

	if _, err := metricsmap.Metrics.OpenOrCreate(); err != nil {
		return err
	}

	if _, err := tunnel.TunnelMap.OpenOrCreate(); err != nil {
		return err
	}

	if err := openServiceMaps(); err != nil {
		log.WithError(err).Fatal("Unable to open service maps")
	}

	// Set up the list of IPCache listeners in the daemon, to be
	// used by syncLXCMap().
	ipcache.IPIdentityCache.SetListeners([]ipcache.IPIdentityMappingListener{
		&envoy.NetworkPolicyHostsCache,
		bpfIPCache.NewListener(d),
	})

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
			DoFunc: func(ctx context.Context) error {
				return d.syncLXCMap()
			},
			RunInterval: 5 * time.Second,
		})

	// Start the controller for periodic sync of the metrics map with
	// the prometheus server.
	controller.NewManager().UpdateController("metricsmap-bpf-prom-sync",
		controller.ControllerParams{
			DoFunc:      metricsmap.SyncMetricsMap,
			RunInterval: 5 * time.Second,
		})

	// Clean all lb entries
	if !option.Config.RestoreState {
		log.Debug("cleaning up all BPF LB maps")

		d.loadBalancer.BPFMapMU.Lock()
		defer d.loadBalancer.BPFMapMU.Unlock()

		if option.Config.EnableIPv6 {
			if err := lbmap.Service6Map.DeleteAll(); err != nil {
				return err
			}
			if err := lbmap.RRSeq6Map.DeleteAll(); err != nil {
				return err
			}
		}
		if err := d.RevNATDeleteAll(); err != nil {
			return err
		}

		if option.Config.EnableIPv4 {
			if err := lbmap.Service4Map.DeleteAll(); err != nil {
				return err
			}
			if err := lbmap.RRSeq4Map.DeleteAll(); err != nil {
				return err
			}
		}

		// If we are not restoring state, all endpoints can be
		// deleted. Entries will be re-populated.
		lxcmap.LXCMap.DeleteAll()
	}

	return nil
}

func (d *Daemon) init() error {
	globalsDir := option.Config.GetGlobalsDir()
	if err := os.MkdirAll(globalsDir, defaults.RuntimePathRights); err != nil {
		log.WithError(err).WithField(logfields.Path, globalsDir).Fatal("Could not create runtime directory")
	}

	if err := os.Chdir(option.Config.StateDir); err != nil {
		log.WithError(err).WithField(logfields.Path, option.Config.StateDir).Fatal("Could not change to runtime directory")
	}

	// Remove any old sockops and re-enable with _new_ programs if flag is set
	sockops.SockmapDisable()
	sockops.SkmsgDisable()

	if !option.Config.DryMode {
		if err := d.createNodeConfigHeaderfile(); err != nil {
			return err
		}

		if option.Config.SockopsEnable {
			disableSockops := func(err error) {
				option.Config.SockopsEnable = false
				log.WithError(err).Warn("Disabled '--sockops-enable' due to missing BPF kernel support")
			}
			eppolicymap.CreateEPPolicyMap()
			if err := sockops.SockmapEnable(); err != nil {
				disableSockops(err)
			} else if err := sockops.SkmsgEnable(); err != nil {
				disableSockops(err)
			} else {
				sockmap.SockmapCreate()
			}
		}

		if err := d.compileBase(); err != nil {
			return err
		}
	}

	return nil
}

func (d *Daemon) createNodeConfigHeaderfile() error {
	nodeConfigPath := option.Config.GetNodeConfigPath()
	f, err := os.Create(nodeConfigPath)
	if err != nil {
		log.WithError(err).WithField(logfields.Path, nodeConfigPath).Fatal("Failed to create node configuration file")
		return err
	}
	defer f.Close()

	if err = d.datapath.WriteNodeConfig(f, &d.nodeDiscovery.LocalConfig); err != nil {
		log.WithError(err).WithField(logfields.Path, nodeConfigPath).Fatal("Failed to write node configuration file")
		return err
	}
	return nil
}

// syncLXCMap adds local host enties to bpf lxcmap, as well as
// ipcache, if needed, and also notifies the daemon and network policy
// hosts cache if changes were made.
func (d *Daemon) syncLXCMap() error {
	// TODO: Update addresses first, in case node addressing has changed.
	// TODO: Once these start changing on runtime, figure out the locking strategy.
	specialIdentities := []identity.IPIdentityPair{}

	if option.Config.EnableIPv4 {
		ip := node.GetInternalIPv4()
		if len(ip) > 0 {
			specialIdentities = append(specialIdentities,
				identity.IPIdentityPair{
					IP: ip,
					ID: identity.ReservedIdentityHost,
				})
		}

		ip = node.GetExternalIPv4()
		if len(ip) > 0 {
			specialIdentities = append(specialIdentities,
				identity.IPIdentityPair{
					IP: ip,
					ID: identity.ReservedIdentityHost,
				})
		}

		specialIdentities = append(specialIdentities,
			identity.IPIdentityPair{
				IP:   net.IPv4zero,
				Mask: net.CIDRMask(0, net.IPv4len*8),
				ID:   identity.ReservedIdentityWorld,
			})
	}

	if option.Config.EnableIPv6 {
		ip := node.GetIPv6()
		if len(ip) > 0 {
			specialIdentities = append(specialIdentities,
				identity.IPIdentityPair{
					IP: ip,
					ID: identity.ReservedIdentityHost,
				})
		}

		ip = node.GetIPv6Router()
		if len(ip) > 0 {
			specialIdentities = append(specialIdentities,
				identity.IPIdentityPair{
					IP: ip,
					ID: identity.ReservedIdentityHost,
				})
		}

		specialIdentities = append(specialIdentities,
			identity.IPIdentityPair{
				IP:   net.IPv6zero,
				Mask: net.CIDRMask(0, net.IPv6len*8),
				ID:   identity.ReservedIdentityWorld,
			})
	}

	existingEndpoints, err := lxcmap.DumpToMap()
	if err != nil {
		return err
	}

	for _, ipIDPair := range specialIdentities {
		hostKey := node.GetIPsecKeyIdentity()
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

		delete(existingEndpoints, ipIDPair.IP.String())

		// Upsert will not propagate (reserved:foo->ID) mappings across the cluster,
		// and we specifically don't want to do so.
		ipcache.IPIdentityCache.Upsert(ipIDPair.PrefixString(), nil, hostKey, ipcache.Identity{
			ID:     ipIDPair.ID,
			Source: ipcache.FromAgentLocal,
		})
	}

	for hostIP, info := range existingEndpoints {
		if ip := net.ParseIP(hostIP); info.IsHost() && ip != nil {
			if err := lxcmap.DeleteEntry(ip); err != nil {
				log.WithError(err).WithFields(logrus.Fields{
					logfields.IPAddr: hostIP,
				}).Warn("Unable to delete obsolete host IP from BPF map")
			} else {
				log.Debugf("Removed outdated host ip %s from endpoint map", hostIP)
			}
		}
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
	prefixLengths4 := ipcachemap.IPCache.GetMaxPrefixLengths(false)
	prefixLengths6 := ipcachemap.IPCache.GetMaxPrefixLengths(true)
	counter := counter.NewPrefixLengthCounter(prefixLengths6, prefixLengths4)

	// This is a bit ugly, but there's not a great way to define an IPNet
	// without parsing strings, etc.
	defaultPrefixes := []*net.IPNet{
		// IPv4
		createIPNet(0, net.IPv4len*8),             // world
		createIPNet(net.IPv4len*8, net.IPv4len*8), // hosts

		// IPv6
		createIPNet(0, net.IPv6len*8),             // world
		createIPNet(net.IPv6len*8, net.IPv6len*8), // hosts
	}
	_, err := counter.Add(defaultPrefixes)
	if err != nil {
		log.WithError(err).Fatal("Failed to create default prefix lengths")
	}
	return counter
}

func deleteHostDevice() {
	link, err := netlink.LinkByName(option.Config.HostDevice)
	if err != nil {
		log.WithError(err).Warningf("Unable to lookup host device %s. No old cilium_host interface exists", option.Config.HostDevice)
		return
	}

	if err := netlink.LinkDel(link); err != nil {
		log.WithError(err).Errorf("Unable to delete host device %s to change allocation CIDR", option.Config.HostDevice)
	}
}

func (d *Daemon) prepareAllocationCIDR(family datapath.NodeAddressingFamily) (routerIP net.IP, err error) {
	// Reserve the IPv4 external node IP within the allocation range if
	// required.
	allocRange := family.AllocationCIDR()
	nodeIP := family.PrimaryExternal()
	if allocRange.Contains(nodeIP) {
		err = d.ipam.AllocateIP(nodeIP, "node")
		if err != nil {
			err = fmt.Errorf("Unable to allocate external IPv4 node IP %s from allocation range %s: %s",
				nodeIP, allocRange, err)
			return
		}
	}

	routerIP = family.Router()
	if routerIP != nil && !allocRange.Contains(routerIP) {
		log.Warningf("Detected allocation CIDR change to %s, previous router IP %s", allocRange, routerIP)

		// The restored router IP is not part of the allocation range.
		// This indicates that the allocation range has changed.
		if !option.Config.IsFlannelMasterDeviceSet() {
			deleteHostDevice()
		}

		// force re-allocation of the router IP
		routerIP = nil
	}

	if routerIP == nil {
		routerIP = ip.GetNextIP(family.AllocationCIDR().IP)
	}

	err = d.ipam.AllocateIP(routerIP, "router")
	if err != nil {
		err = fmt.Errorf("Unable to allocate IPv4 router IP %s from allocation range %s: %s",
			routerIP, allocRange, err)
		return
	}

	return
}

// NewDaemon creates and returns a new Daemon with the parameters set in c.
func NewDaemon(dp datapath.Datapath) (*Daemon, *endpointRestoreState, error) {
	var authKeySize int

	bootstrapStats.daemonInit.Start()
	// Validate the daemon-specific global options.
	if err := option.Config.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid daemon configuration: %s", err)
	}

	ctmap.InitMapInfo(option.Config.CTMapEntriesGlobalTCP, option.Config.CTMapEntriesGlobalAny)

	if option.Config.EnableIPSec {
		var spi uint8
		var err error

		authKeySize, spi, err = ipsec.LoadIPSecKeysFile(option.Config.IPSecKeyFile)
		if err != nil {
			return nil, nil, err
		}
		if option.Config.EnableIPv6 {
			if err := ipsec.EnableIPv6Forwarding(); err != nil {
				return nil, nil, err
			}
		}
		node.SetIPsecKeyIdentity(spi)
	}

	mtuConfig := mtu.NewConfiguration(authKeySize, option.Config.EnableIPSec, option.Config.Tunnel != option.TunnelDisabled, option.Config.MTU)

	nodeMngr, err := nodemanager.NewManager("all", dp.Node())
	if err != nil {
		return nil, nil, err
	}

	d := Daemon{
		loadBalancer:      loadbalancer.NewLoadBalancer(),
		k8sSvcCache:       k8s.NewServiceCache(),
		policy:            policy.NewPolicyRepository(),
		uniqueID:          map[uint64]context.CancelFunc{},
		nodeMonitor:       monitorLaunch.NewNodeMonitor(option.Config.MonitorQueueSize),
		prefixLengths:     createPrefixLengthCounter(),
		k8sResourceSynced: map[string]chan struct{}{},

		buildEndpointSem: semaphore.NewWeighted(int64(numWorkerThreads())),
		compilationMutex: new(lock.RWMutex),
		mtuConfig:        mtuConfig,
		datapath:         dp,
		nodeDiscovery:    nodediscovery.NewNodeDiscovery(nodeMngr, mtuConfig),
	}
	bootstrapStats.daemonInit.End(true)

	// Open or create BPF maps.
	bootstrapStats.mapsInit.Start()
	err = d.initMaps()
	bootstrapStats.mapsInit.EndError(err)
	if err != nil {
		log.WithError(err).Error("Error while opening/creating BPF maps")
		return nil, nil, err
	}

	// Read the service IDs of existing services from the BPF map and
	// reserve them. This must be done *before* connecting to the
	// Kubernetes apiserver and serving the API to ensure service IDs are
	// not changing across restarts or that a new service could accidentally
	// use an existing service ID.
	// Also, create missing v2 services from the corresponding legacy ones.
	if option.Config.RestoreState && !option.Config.DryMode {
		bootstrapStats.restore.Start()
		restoreServices()
		bootstrapStats.restore.End(true)
	}

	t, err := trigger.NewTrigger(trigger.Parameters{
		Name:              "policy_update",
		PrometheusMetrics: true,
		MinInterval:       time.Second,
		TriggerFunc:       d.policyUpdateTrigger,
	})
	if err != nil {
		return nil, nil, err
	}
	d.policyTrigger = t

	debug.RegisterStatusObject("k8s-service-cache", &d.k8sSvcCache)

	bootstrapStats.k8sInit.Start()
	k8s.Configure(option.Config.K8sAPIServer, option.Config.K8sKubeConfigPath)
	bootstrapStats.k8sInit.End(true)
	d.runK8sServiceHandler()
	policyApi.InitEntities(option.Config.ClusterName)

	bootstrapStats.workloadsInit.Start()
	workloads.Init(&d)
	bootstrapStats.workloadsInit.End(true)

	bootstrapStats.cleanup.Start()
	err = d.clearCiliumVeths()
	bootstrapStats.cleanup.EndError(err)
	if err != nil {
		log.WithError(err).Warning("Unable to clean stale endpoint interfaces")
	}

	if k8s.IsEnabled() {
		bootstrapStats.k8sInit.Start()
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

		bootstrapStats.k8sInit.End(true)
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
	bootstrapStats.ipam.Start()
	log.Info("Initializing node addressing")

	node.SetIPv4ClusterCidrMaskSize(option.Config.IPv4ClusterCIDRMaskSize)

	if option.Config.IPv4Range != AutoCIDR {
		allocCIDR, err := cidr.ParseCIDR(option.Config.IPv4Range)
		if err != nil {
			log.WithError(err).WithField(logfields.V4Prefix, option.Config.IPv4Range).Fatal("Invalid IPv4 allocation prefix")
		}
		node.SetIPv4AllocRange(allocCIDR)
	}

	if option.Config.IPv6Range != AutoCIDR {
		_, net, err := net.ParseCIDR(option.Config.IPv6Range)
		if err != nil {
			log.WithError(err).WithField(logfields.V6Prefix, option.Config.IPv6Range).Fatal("Invalid IPv6 allocation prefix")
		}

		if err := node.SetIPv6NodeRange(net); err != nil {
			log.WithError(err).WithField(logfields.V6Prefix, net).Fatal("Invalid per node IPv6 allocation prefix")
		}
	}

	if err := node.AutoComplete(); err != nil {
		log.WithError(err).Fatal("Cannot autocomplete node addresses")
	}

	// Set up ipam conf after init() because we might be running d.conf.KVStoreIPv4Registration
	log.WithFields(logrus.Fields{
		logfields.V4Prefix: dp.LocalNodeAddressing().IPv4().AllocationCIDR(),
		logfields.V6Prefix: dp.LocalNodeAddressing().IPv6().AllocationCIDR(),
	}).Info("Initializing IPAM")
	d.ipam = ipam.NewIPAM(dp.LocalNodeAddressing(), ipam.Configuration{
		EnableIPv4: option.Config.EnableIPv4,
		EnableIPv6: option.Config.EnableIPv6,
	})
	bootstrapStats.ipam.End(true)

	if option.Config.WorkloadsEnabled() {
		bootstrapStats.workloadsInit.Start()
		// workaround for to use the values of the deprecated dockerEndpoint
		// variable if it is set with a different value than defaults.
		defaultDockerEndpoint := workloads.GetRuntimeDefaultOpt(workloads.Docker, "endpoint")
		if defaultDockerEndpoint != option.Config.DockerEndpoint {
			option.Config.ContainerRuntimeEndpoint[string(workloads.Docker)] = option.Config.DockerEndpoint
			log.Warn(`"docker" flag is deprecated.` +
				`Please use "--container-runtime-endpoint=docker=` + defaultDockerEndpoint + `" instead`)
		}

		opts := make(map[workloads.WorkloadRuntimeType]map[string]string)
		for rt, ep := range option.Config.ContainerRuntimeEndpoint {
			opts[workloads.WorkloadRuntimeType(rt)] = make(map[string]string)
			opts[workloads.WorkloadRuntimeType(rt)][workloads.EpOpt] = ep
		}
		if opts[workloads.Docker] == nil {
			opts[workloads.Docker] = make(map[string]string)
		}
		opts[workloads.Docker][workloads.DatapathModeOpt] = option.Config.DatapathMode

		// Workloads must be initialized after IPAM has started as it requires
		// to allocate IPs.
		if err := workloads.Setup(d.ipam, option.Config.Workloads, opts); err != nil {
			return nil, nil, fmt.Errorf("unable to setup workload: %s", err)
		}

		log.Infof("Container runtime options set: %s", workloads.GetRuntimeOptions())
		bootstrapStats.workloadsInit.End(true)
	}

	bootstrapStats.restore.Start()
	// restore endpoints before any IPs are allocated to avoid eventual IP
	// conflicts later on, otherwise any IP conflict will result in the
	// endpoint not being able to be restored.
	restoredEndpoints, err := d.restoreOldEndpoints(option.Config.StateDir, true)
	if err != nil {
		log.WithError(err).Error("Unable to restore existing endpoints")
	}
	bootstrapStats.restore.End(true)

	bootstrapStats.ipam.Start()
	if option.Config.EnableIPv4 {
		routerIP, err := d.prepareAllocationCIDR(dp.LocalNodeAddressing().IPv4())
		if err != nil {
			return nil, nil, err
		}
		if routerIP != nil {
			node.SetInternalIPv4(routerIP)
		}
	}

	if option.Config.EnableIPv6 {
		routerIP, err := d.prepareAllocationCIDR(dp.LocalNodeAddressing().IPv6())
		if err != nil {
			return nil, nil, err
		}
		if routerIP != nil {
			node.SetIPv6Router(routerIP)
		}
	}

	log.Info("Addressing information:")
	log.Infof("  Cluster-Name: %s", option.Config.ClusterName)
	log.Infof("  Cluster-ID: %d", option.Config.ClusterID)
	log.Infof("  Local node-name: %s", node.GetName())
	log.Infof("  Node-IPv6: %s", node.GetIPv6())

	if option.Config.EnableIPv6 {
		log.Infof("  IPv6 node prefix: %s", node.GetIPv6NodeRange())
		log.Infof("  IPv6 allocation prefix: %s", node.GetIPv6AllocRange())
		log.Infof("  IPv6 router address: %s", node.GetIPv6Router())
	}

	log.Infof("  External-Node IPv4: %s", node.GetExternalIPv4())
	log.Infof("  Internal-Node IPv4: %s", node.GetInternalIPv4())

	if option.Config.EnableIPv4 {
		log.Infof("  Cluster IPv4 prefix: %s", node.GetIPv4ClusterRange())
		log.Infof("  IPv4 allocation prefix: %s", node.GetIPv4AllocRange())

		// Allocate IPv4 service loopback IP
		loopbackIPv4, err := d.ipam.AllocateNextFamily(ipam.IPv4, "loopback")
		if err != nil {
			return nil, restoredEndpoints, fmt.Errorf("Unable to reserve IPv4 loopback address: %s", err)
		}
		node.SetIPv4Loopback(loopbackIPv4)
		log.Infof("  Loopback IPv4: %s", node.GetIPv4Loopback().String())
	}
	bootstrapStats.ipam.End(true)

	bootstrapStats.healthCheck.Start()
	if option.Config.EnableHealthChecking {
		if option.Config.EnableIPv4 {
			health4, err := d.ipam.AllocateNextFamily(ipam.IPv4, "health")
			if err != nil {
				return nil, restoredEndpoints, fmt.Errorf("unable to allocate health IPs: %s,see https://cilium.link/ipam-range-full", err)
			}

			d.nodeDiscovery.LocalNode.IPv4HealthIP = health4
			log.Debugf("IPv4 health endpoint address: %s", health4)
		}

		if option.Config.EnableIPv6 {
			health6, err := d.ipam.AllocateNextFamily(ipam.IPv6, "health")
			if err != nil {
				if d.nodeDiscovery.LocalNode.IPv4HealthIP != nil {
					d.ipam.ReleaseIP(d.nodeDiscovery.LocalNode.IPv4HealthIP)
				}
				return nil, restoredEndpoints, fmt.Errorf("unable to allocate health IPs: %s,see https://cilium.link/ipam-range-full", err)
			}

			d.nodeDiscovery.LocalNode.IPv6HealthIP = health6
			log.Debugf("IPv6 health endpoint address: %s", health6)
		}
	}
	bootstrapStats.healthCheck.End(true)

	// Annotation of the k8s node must happen after discovery of the
	// PodCIDR range and allocation of the health IPs.
	if k8s.IsEnabled() {
		bootstrapStats.k8sInit.Start()
		log.WithFields(logrus.Fields{
			logfields.V4Prefix:       node.GetIPv4AllocRange(),
			logfields.V6Prefix:       node.GetIPv6NodeRange(),
			logfields.V4HealthIP:     d.nodeDiscovery.LocalNode.IPv4HealthIP,
			logfields.V6HealthIP:     d.nodeDiscovery.LocalNode.IPv6HealthIP,
			logfields.V4CiliumHostIP: node.GetInternalIPv4(),
			logfields.V6CiliumHostIP: node.GetIPv6Router(),
		}).Info("Annotating k8s node")

		err := k8s.Client().AnnotateNode(node.GetName(),
			node.GetIPv4AllocRange(), node.GetIPv6NodeRange(),
			d.nodeDiscovery.LocalNode.IPv4HealthIP, d.nodeDiscovery.LocalNode.IPv6HealthIP,
			node.GetInternalIPv4(), node.GetIPv6Router())
		if err != nil {
			log.WithError(err).Warning("Cannot annotate k8s node with CIDR range")
		}
		bootstrapStats.k8sInit.End(true)
	}

	d.nodeDiscovery.StartDiscovery(node.GetName())

	// This needs to be done after the node addressing has been configured
	// as the node address is required as suffix.
	go cache.InitIdentityAllocator(&d)

	bootstrapStats.clusterMeshInit.Start()
	if path := option.Config.ClusterMeshConfig; path != "" {
		if option.Config.ClusterID == 0 {
			log.Info("Cluster-ID is not specified, skipping ClusterMesh initialization")
		} else {
			log.WithField("path", path).Info("Initializing ClusterMesh routing")
			clustermesh, err := clustermesh.NewClusterMesh(clustermesh.Configuration{
				Name:            "clustermesh",
				ConfigDirectory: path,
				NodeKeyCreator:  nodeStore.KeyCreator,
				ServiceMerger:   &d.k8sSvcCache,
				NodeManager:     nodeMngr,
			})
			if err != nil {
				log.WithError(err).Fatal("Unable to initialize ClusterMesh")
			}

			d.clustermesh = clustermesh
		}
	}
	bootstrapStats.clusterMeshInit.End(true)

	bootstrapStats.bpfBase.Start()
	err = d.init()
	bootstrapStats.bpfBase.EndError(err)
	if err != nil {
		log.WithError(err).Error("Error while initializing daemon")
		return nil, restoredEndpoints, err
	}
	if err := loader.RestoreTemplates(option.Config.StateDir); err != nil {
		log.WithError(err).Error("Unable to restore previous BPF templates")
	}

	// Start watcher for endpoint IP --> identity mappings in key-value store.
	// this needs to be done *after* init() for the daemon in that function,
	// we populate the IPCache with the host's IP(s).
	ipcache.InitIPIdentityWatcher()
	identitymanager.Subscribe(d.policy)

	bootstrapStats.proxyStart.Start()
	// FIXME: Make the port range configurable.
	d.l7Proxy = proxy.StartProxySupport(10000, 20000, option.Config.RunDir,
		option.Config.AccessLog, &d, option.Config.AgentLabels, d.datapath)
	bootstrapStats.proxyStart.End(true)

	bootstrapStats.fqdn.Start()
	if err := fqdn.ConfigFromResolvConf(); err != nil {
		bootstrapStats.fqdn.EndError(err)
		return nil, nil, err
	}

	err = d.bootstrapFQDN(restoredEndpoints, option.Config.ToFQDNsPreCache)
	if err != nil {
		bootstrapStats.fqdn.EndError(err)
		return nil, restoredEndpoints, err
	}
	bootstrapStats.fqdn.End(true)

	return &d, restoredEndpoints, nil
}

// Close shuts down a daemon
func (d *Daemon) Close() {
	if d.policyTrigger != nil {
		d.policyTrigger.Shutdown()
	}
	d.nodeDiscovery.Close()
}

func (d *Daemon) attachExistingInfraContainers() {
	m, err := workloads.Client().GetAllInfraContainersPID()
	if err != nil {
		log.WithError(err).Error("Unable to get all infra containers PIDs")
		return
	}
	log.Debugf("Containers found %+v", m)
	for containerID, pid := range m {
		epModel, err := connector.DeriveEndpointFrom(option.Config.FlannelMasterDevice, containerID, pid)
		if err != nil {
			log.WithError(err).WithField(logfields.ContainerID, containerID).
				Warning("Unable to derive endpoint from existing infra container")
			continue
		}
		log.Debugf("Adding endpoint %+v", epModel)
		ep, _, err := d.createEndpoint(context.Background(), epModel)
		if err != nil {
			log.WithError(err).WithField(logfields.ContainerID, containerID).
				Warning("Unable to attach existing infra container")
			continue
		}
		log.WithFields(logrus.Fields{
			logfields.ContainerID: epModel.ContainerID,
			logfields.EndpointID:  ep.ID,
		}).Info("Attached BPF program to existing container")
	}
}

// TriggerReloadWithoutCompile causes all BPF programs and maps to be reloaded,
// without recompiling the datapath logic for each endpoint. It first attempts
// to recompile the base programs, and if this fails returns an error. If base
// program load is successful, it subsequently triggers regeneration of all
// endpoints and returns a waitgroup that may be used by the caller to wait for
// all endpoint regeneration to complete.
//
// If an error is returned, then no regeneration was successful. If no error
// is returned, then the base programs were successfully regenerated, but
// endpoints may or may not have successfully regenerated.
func (d *Daemon) TriggerReloadWithoutCompile(reason string) (*sync.WaitGroup, error) {
	log.Debugf("BPF reload triggered from %s", reason)
	if err := d.compileBase(); err != nil {
		return nil, fmt.Errorf("Unable to recompile base programs from %s: %s", reason, err)
	}

	regenRequest := &endpoint.ExternalRegenerationMetadata{
		Reason:            reason,
		RegenerationLevel: endpoint.RegenerateWithDatapathLoad,
	}
	return endpointmanager.RegenerateAllEndpoints(d, regenRequest), nil
}

func changedOption(key string, value option.OptionSetting, data interface{}) {
	d := data.(*Daemon)
	if key == option.Debug {
		// Set the debug toggle (this can be a no-op)
		logging.ToggleDebugLogs(d.DebugEnabled())
		// Reflect log level change to proxies
		proxy.ChangeLogLevel(logging.GetLevel(logging.DefaultLogger))
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

	cfgSpec := params.Configuration

	om, err := option.Config.Opts.Library.ValidateConfigurationMap(cfgSpec.Options)
	if err != nil {
		msg := fmt.Errorf("Invalid configuration option %s", err)
		return api.Error(PatchConfigBadRequestCode, msg)
	}

	// Serialize configuration updates to the daemon.
	option.Config.ConfigPatchMutex.Lock()
	defer option.Config.ConfigPatchMutex.Unlock()

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

	changes += option.Config.Opts.ApplyValidated(om, changedOption, d)

	log.WithField("count", changes).Debug("Applied changes to daemon's configuration")

	if changes > 0 {
		// Only recompile if configuration has changed.
		log.Debug("daemon configuration has changed; recompiling base programs")
		if err := d.compileBase(); err != nil {
			msg := fmt.Errorf("Unable to recompile base programs: %s", err)
			return api.Error(PatchConfigFailureCode, msg)
		}
		d.TriggerPolicyUpdates(true, "agent configuration update")
	}

	return NewPatchConfigOK()
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
		Addressing:       node.GetNodeAddressing(),
		K8sConfiguration: k8s.GetKubeconfigPath(),
		K8sEndpoint:      k8s.GetAPIServer(),
		NodeMonitor:      d.nodeMonitor.State(),
		KvstoreConfiguration: &models.KVstoreConfiguration{
			Type:    option.Config.KVStore,
			Options: option.Config.KVStoreOpt,
		},
		Realized:     spec,
		DeviceMTU:    int64(d.mtuConfig.GetDeviceMTU()),
		RouteMTU:     int64(d.mtuConfig.GetRouteMTU()),
		DatapathMode: models.DatapathMode(option.Config.DatapathMode),
		IpvlanConfiguration: &models.IpvlanConfiguration{
			MasterDeviceIndex: int64(option.Config.Ipvlan.MasterDeviceIndex),
			OperationMode:     option.Config.Ipvlan.OperationMode,
		},
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
	log.Info("Removing stale endpoint interfaces")

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
				log.WithError(err).Warningf("Unable to delete stale veth device %s", v.Attrs().Name)
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
func (d *Daemon) SendNotification(typ monitorAPI.AgentNotification, text string) error {
	if option.Config.DryMode {
		return nil
	}
	event := monitorAPI.AgentNotify{Type: typ, Text: text}
	return d.nodeMonitor.SendEvent(monitorAPI.MessageTypeAgent, event)
}

// NewProxyLogRecord is invoked by the proxy accesslog on each new access log entry
func (d *Daemon) NewProxyLogRecord(l *logger.LogRecord) error {
	return d.nodeMonitor.SendEvent(monitorAPI.MessageTypeAccessLog, l.LogRecord)
}

// GetNodeSuffix returns the suffix to be appended to kvstore keys of this
// agent
func (d *Daemon) GetNodeSuffix() string {
	var ip net.IP

	switch {
	case option.Config.EnableIPv4:
		ip = node.GetExternalIPv4()
	case option.Config.EnableIPv6:
		ip = node.GetIPv6()
	}

	if ip == nil {
		log.Fatal("Node IP not available yet")
	}

	return ip.String()
}
