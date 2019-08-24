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
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	health "github.com/cilium/cilium/cilium-health/launch"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/datapath"
	bpfIPCache "github.com/cilium/cilium/pkg/datapath/ipcache"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/datapath/prefilter"
	"github.com/cilium/cilium/pkg/debug"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint/connector"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/endpointsynchronizer"
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
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/maps/sockmap"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	monitoragent "github.com/cilium/cilium/pkg/monitor/agent"
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
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/status"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/cilium/cilium/pkg/workloads"
	cnitypes "github.com/cilium/cilium/plugins/cilium-cni/types"

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
	initArgHostReachableServicesUDP
	initArgCgroupRoot
	initArgBpffsRoot
	initArgNodePort
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

	monitorAgent *monitoragent.Agent
	ciliumHealth *health.CiliumHealth

	// dnsNameManager tracks which api.FQDNSelector are present in policy which
	// apply to locally running endpoints.
	dnsNameManager *fqdn.NameManager

	// dnsPoller polls DNS names and sends them to dnsNameManager
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

	netConf *cnitypes.NetConf

	// iptablesManager deals with all iptables rules installed in the node
	iptablesManager rulesManager

	endpointManager *endpointmanager.EndpointManager
}

// Datapath returns a reference to the datapath implementation.
func (d *Daemon) Datapath() datapath.Datapath {
	return d.datapath
}

// UpdateProxyRedirect updates the redirect rules in the proxy for a particular
// endpoint using the provided L4 filter. Returns the allocated proxy port
func (d *Daemon) UpdateProxyRedirect(e regeneration.EndpointUpdater, l4 *policy.L4Filter, proxyWaitGroup *completion.WaitGroup) (uint16, error, revert.FinalizeFunc, revert.RevertFunc) {
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
func (d *Daemon) RemoveProxyRedirect(e regeneration.EndpointInfoSource, id string, proxyWaitGroup *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc) {
	if d.l7Proxy == nil {
		return nil, nil, nil
	}

	log.WithFields(logrus.Fields{
		logfields.EndpointID: e.GetID(),
		logfields.L4PolicyID: id,
	}).Debug("Removing redirect to endpoint")
	return d.l7Proxy.RemoveRedirect(id, proxyWaitGroup)
}

// UpdateNetworkPolicy adds or updates a network policy in the set
// published to L7 proxies.
func (d *Daemon) UpdateNetworkPolicy(e regeneration.EndpointUpdater, policy *policy.L4Policy,
	proxyWaitGroup *completion.WaitGroup) (error, revert.RevertFunc) {
	if d.l7Proxy == nil {
		return fmt.Errorf("can't update network policy, proxy disabled"), nil
	}
	err, revertFunc := d.l7Proxy.UpdateNetworkPolicy(e, policy, e.GetIngressPolicyEnabledLocked(),
		e.GetEgressPolicyEnabledLocked(), proxyWaitGroup)
	return err, revert.RevertFunc(revertFunc)
}

// RemoveNetworkPolicy removes a network policy from the set published to
// L7 proxies.
func (d *Daemon) RemoveNetworkPolicy(e regeneration.EndpointInfoSource) {
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

// GetCIDRPrefixLengths returns the sorted list of unique prefix lengths used
// by CIDR policies.
func (d *Daemon) GetCIDRPrefixLengths() (s6, s4 []int) {
	return d.prefixLengths.ToBPFData()
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

// initMaps opens all BPF maps (and creates them if they do not exist). This
// must be done *before* any operations which read BPF maps, especially
// restoring endpoints and services.
func (d *Daemon) initMaps() error {
	if option.Config.DryMode {
		return nil
	}

	// Delete old proxymaps if left over from an upgrade.
	// TODO: Remove this code when Cilium 1.6 is the oldest supported release
	for _, name := range []string{"cilium_proxy4", "cilium_proxy6"} {
		path := bpf.MapPath(name)
		if _, err := os.Stat(path); err == nil {
			if err = os.RemoveAll(path); err == nil {
				log.Infof("removed legacy proxymap file %s", path)
			}
		}
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
	// used by syncEndpointsAndHostIPs()
	// xDS cache will be added later by calling AddListener(), but only if necessary.
	ipcache.IPIdentityCache.SetListeners([]ipcache.IPIdentityMappingListener{
		bpfIPCache.NewListener(d),
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
			if err := lbmap.Service6MapV2.DeleteAll(); err != nil {
				return err
			}
			if err := lbmap.RRSeq6MapV2.DeleteAll(); err != nil {
				return err
			}
			if err := lbmap.Backend6Map.DeleteAll(); err != nil {
				return err
			}
		}
		if err := d.RevNATDeleteAll(); err != nil {
			return err
		}

		if option.Config.EnableIPv4 {
			if err := lbmap.Service4MapV2.DeleteAll(); err != nil {
				return err
			}
			if err := lbmap.RRSeq4MapV2.DeleteAll(); err != nil {
				return err
			}
			if err := lbmap.Backend4Map.DeleteAll(); err != nil {
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

		if err := d.syncEndpointsAndHostIPs(); err != nil {
			return err
		}

		// Start the controller for periodic sync. The purpose of the
		// controller is to ensure that endpoints and host IPs entries are
		// reinserted to the bpf maps if they are ever removed from them.
		controller.NewManager().UpdateController("sync-endpoints-and-host-ips",
			controller.ControllerParams{
				DoFunc: func(ctx context.Context) error {
					return d.syncEndpointsAndHostIPs()
				},
				RunInterval: time.Minute,
			})
	}

	return nil
}

// syncLXCMap adds local host enties to bpf lxcmap, as well as
// ipcache, if needed, and also notifies the daemon and network policy
// hosts cache if changes were made.
func (d *Daemon) syncEndpointsAndHostIPs() error {
	specialIdentities := []identity.IPIdentityPair{}

	if option.Config.EnableIPv4 {
		addrs, err := d.datapath.LocalNodeAddressing().IPv4().LocalAddresses()
		if err != nil {
			log.WithError(err).Warning("Unable to list local IPv4 addresses")
		}

		for _, ip := range addrs {
			if option.Config.IsExcludedLocalAddress(ip) {
				continue
			}

			if len(ip) > 0 {
				specialIdentities = append(specialIdentities,
					identity.IPIdentityPair{
						IP: ip,
						ID: identity.ReservedIdentityHost,
					})
			}
		}

		specialIdentities = append(specialIdentities,
			identity.IPIdentityPair{
				IP:   net.IPv4zero,
				Mask: net.CIDRMask(0, net.IPv4len*8),
				ID:   identity.ReservedIdentityWorld,
			})
	}

	if option.Config.EnableIPv6 {
		addrs, err := d.datapath.LocalNodeAddressing().IPv6().LocalAddresses()
		if err != nil {
			log.WithError(err).Warning("Unable to list local IPv4 addresses")
		}

		addrs = append(addrs, node.GetIPv6Router())
		for _, ip := range addrs {
			if option.Config.IsExcludedLocalAddress(ip) {
				continue
			}

			if len(ip) > 0 {
				specialIdentities = append(specialIdentities,
					identity.IPIdentityPair{
						IP: ip,
						ID: identity.ReservedIdentityHost,
					})
			}
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
			Source: source.Local,
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

			ipcache.IPIdentityCache.Delete(hostIP, source.Local)
		}
	}

	return nil
}

// createPrefixLengthCounter wraps around the counter library, providing
// references to prefix lengths that will always be present.
func createPrefixLengthCounter() *counter.PrefixLengthCounter {
	max6, max4 := ipcachemap.IPCache.GetMaxPrefixLengths()
	return counter.DefaultPrefixLengthCounter(max6, max4)
}

type rulesManager interface {
	RemoveRules()
	InstallRules(ifName string) error
	TransientRulesStart(ifName string) error
	TransientRulesEnd(quiet bool)
}

// NewDaemon creates and returns a new Daemon with the parameters set in c.
func NewDaemon(dp datapath.Datapath, iptablesManager rulesManager) (*Daemon, *endpointRestoreState, error) {
	var (
		err           error
		netConf       *cnitypes.NetConf
		configuredMTU = option.Config.MTU
	)

	bootstrapStats.daemonInit.Start()

	// Validate the daemon-specific global options.
	if err := option.Config.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid daemon configuration: %s", err)
	}

	if option.Config.ReadCNIConfiguration != "" {
		netConf, err = cnitypes.ReadNetConf(option.Config.ReadCNIConfiguration)
		if err != nil {
			log.WithError(err).Fatal("Unable to read CNI configuration")
		}

		if netConf.MTU != 0 {
			configuredMTU = netConf.MTU
			log.WithField("mtu", configuredMTU).Info("Overwriting MTU based on CNI configuration")
		}
	}

	ctmap.InitMapInfo(option.Config.CTMapEntriesGlobalTCP, option.Config.CTMapEntriesGlobalAny,
		option.Config.EnableIPv4, option.Config.EnableIPv6,
	)
	policymap.InitMapInfo(option.Config.PolicyMapMaxEntries)

	if option.Config.DryMode == false {
		if err := bpf.ConfigureResourceLimits(); err != nil {
			log.WithError(err).Fatal("Unable to set memory resource limits")
		}
	}

	authKeySize, err := setupIPSec()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to setup encryption: %s", err)
	}

	mtuConfig := mtu.NewConfiguration(authKeySize, option.Config.EnableIPSec, option.Config.Tunnel != option.TunnelDisabled, configuredMTU)

	nodeMngr, err := nodemanager.NewManager("all", dp.Node())
	if err != nil {
		return nil, nil, err
	}

	identity.UpdateReservedIdentitiesMetrics()
	// Must be done before calling policy.NewPolicyRepository() below.
	identity.InitWellKnownIdentities()

	epMgr := endpointmanager.NewEndpointManager(&endpointsynchronizer.EndpointSynchronizer{})
	epMgr.InitMetrics()

	// Cleanup on exit if running in tandem with Flannel.
	if option.Config.FlannelUninstallOnExit {
		cleanupFuncs.Add(func() {
			for _, ep := range epMgr.GetEndpoints() {
				ep.DeleteBPFProgramLocked()
			}
		})
	}

	d := Daemon{
		loadBalancer:      loadbalancer.NewLoadBalancer(),
		k8sSvcCache:       k8s.NewServiceCache(),
		policy:            policy.NewPolicyRepository(),
		uniqueID:          map[uint64]context.CancelFunc{},
		prefixLengths:     createPrefixLengthCounter(),
		k8sResourceSynced: map[string]chan struct{}{},
		buildEndpointSem:  semaphore.NewWeighted(int64(numWorkerThreads())),
		compilationMutex:  new(lock.RWMutex),
		netConf:           netConf,
		mtuConfig:         mtuConfig,
		datapath:          dp,
		nodeDiscovery:     nodediscovery.NewNodeDiscovery(nodeMngr, mtuConfig),
		iptablesManager:   iptablesManager,
		endpointManager:   epMgr,
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
		Name:            "policy_update",
		MetricsObserver: &policyTriggerMetrics{},
		MinInterval:     option.Config.PolicyTriggerInterval,
		TriggerFunc:     d.policyUpdateTrigger,
	})
	if err != nil {
		return nil, nil, err
	}
	d.policyTrigger = t

	debug.RegisterStatusObject("k8s-service-cache", &d.k8sSvcCache)
	debug.RegisterStatusObject("ipam", d.ipam)

	bootstrapStats.k8sInit.Start()
	k8s.Configure(option.Config.K8sAPIServer, option.Config.K8sKubeConfigPath, defaults.K8sClientQPSLimit, defaults.K8sClientBurst)
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

		if err := k8s.RegisterCRDs(); err != nil {
			log.WithError(err).Fatal("Unable to register CRDs")
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

	d.bootstrapIPAM()

	if err := d.bootstrapWorkloads(); err != nil {
		return nil, nil, err
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

	if err := d.allocateIPs(); err != nil {
		return nil, nil, err
	}

	// Annotation of the k8s node must happen after discovery of the
	// PodCIDR range and allocation of the health IPs.
	if k8s.IsEnabled() && option.Config.AnnotateK8sNode {
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
	} else if !option.Config.AnnotateK8sNode {
		log.Debug("Annotate k8s node is disabled.")
	}

	d.nodeDiscovery.StartDiscovery(node.GetName(), &d)

	// This needs to be done after the node addressing has been configured
	// as the node address is required as suffix.
	// well known identities have already been initialized above
	// Ignore the channel returned by this function, as we want the global
	// identity allocator to run asynchronously.
	cache.InitIdentityAllocator(&d, k8s.CiliumClient(), nil)

	d.bootstrapClusterMesh(nodeMngr)

	bootstrapStats.bpfBase.Start()
	err = d.init()
	// We can only start monitor agent once cilium_event has been set up.
	if option.Config.RunMonitorAgent {
		monitorAgent, err := monitoragent.NewAgent(context.TODO(), defaults.MonitorBufferPages)
		if err != nil {
			return nil, nil, err
		}
		d.monitorAgent = monitorAgent
	}
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
	if option.Config.InstallIptRules {
		d.l7Proxy = proxy.StartProxySupport(10000, 20000, option.Config.RunDir,
			option.Config.AccessLog, &d, option.Config.AgentLabels, d.datapath, d.endpointManager)
	} else {
		log.Warning("L7 proxies not supported when --install-iptables-rules=\"false\"")
	}
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

func setupIPSec() (int, error) {
	if option.Config.EncryptNode == false {
		ipsec.DeleteIPsecEncryptRoute()
	}

	if !option.Config.EnableIPSec {
		return 0, nil
	}

	authKeySize, spi, err := ipsec.LoadIPSecKeysFile(option.Config.IPSecKeyFile)
	if err != nil {
		return 0, err
	}
	node.SetIPsecKeyIdentity(spi)
	return authKeySize, nil
}

func (d *Daemon) bootstrapClusterMesh(nodeMngr *nodemanager.Manager) {
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
}

func (d *Daemon) bootstrapWorkloads() error {
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
		if err := workloads.Setup(d.ipam, d.endpointManager, option.Config.Workloads, opts); err != nil {
			return fmt.Errorf("unable to setup workload: %s", err)
		}

		log.Infof("Container runtime options set: %s", workloads.GetRuntimeOptions())
		bootstrapStats.workloadsInit.End(true)
	}
	return nil
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

	regenRequest := &regeneration.ExternalRegenerationMetadata{
		Reason:            reason,
		RegenerationLevel: regeneration.RegenerateWithDatapathLoad,
	}
	return d.endpointManager.RegenerateAllEndpoints(regenRequest), nil
}

func changedOption(key string, value option.OptionSetting, data interface{}) {
	d := data.(*Daemon)
	if key == option.Debug {
		// Set the debug toggle (this can be a no-op)
		logging.ConfigureLogLevel(d.DebugEnabled())
		// Reflect log level change to proxies
		proxy.ChangeLogLevel(logging.GetLevel(logging.DefaultLogger))
	}
	d.policy.BumpRevision() // force policy recalculation
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

// SendNotification sends an agent notification to the monitor
func (d *Daemon) SendNotification(typ monitorAPI.AgentNotification, text string) error {
	if option.Config.DryMode {
		return nil
	}
	event := monitorAPI.AgentNotify{Type: typ, Text: text}
	return d.monitorAgent.SendEvent(monitorAPI.MessageTypeAgent, event)
}

// NewProxyLogRecord is invoked by the proxy accesslog on each new access log entry
func (d *Daemon) NewProxyLogRecord(l *logger.LogRecord) error {
	return d.monitorAgent.SendEvent(monitorAPI.MessageTypeAccessLog, l.LogRecord)
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

// GetNetConf returns the CNI configuration that was used to initiate the
// daemon instance. This may return nil when no configuration is available.
func (d *Daemon) GetNetConf() *cnitypes.NetConf {
	return d.netConf
}

// UpdateCiliumNodeResource implements nodediscovery.Owner to create/update the
// CiliumNode resource
func (d *Daemon) UpdateCiliumNodeResource() {
	d.nodeDiscovery.UpdateCiliumNodeResource(d)
}
