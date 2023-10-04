// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"

	"github.com/cilium/cilium/api/v1/models"
	health "github.com/cilium/cilium/cilium-health/launch"
	"github.com/cilium/cilium/daemon/cmd/cni"
	"github.com/cilium/cilium/pkg/auth"
	"github.com/cilium/cilium/pkg/bandwidth"
	"github.com/cilium/cilium/pkg/bgp/speaker"
	bgpv1 "github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cgroups/manager"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/datapath/link"
	linuxdatapath "github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/linux/bigtcp"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/datapath/loader"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/debug"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/egressgateway"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/eventqueue"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hubble/observer"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/ipam"
	ipamMetadata "github.com/cilium/cilium/pkg/ipam/metadata"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/k8s"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/l2announcer"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/metrics"
	monitoragent "github.com/cilium/cilium/pkg/monitor/agent"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	policyAPI "github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/recorder"
	"github.com/cilium/cilium/pkg/redirectpolicy"
	"github.com/cilium/cilium/pkg/resiliency"
	"github.com/cilium/cilium/pkg/service"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/status"
	"github.com/cilium/cilium/pkg/trigger"
)

const (
	// AutoCIDR indicates that a CIDR should be allocated
	AutoCIDR = "auto"

	// ConfigModifyQueueSize is the size of the event queue for serializing
	// configuration updates to the daemon
	ConfigModifyQueueSize = 10

	syncHostIPsController = "sync-host-ips"
)

// Daemon is the cilium daemon that is in charge of perform all necessary plumbing,
// monitoring when a LXC starts.
type Daemon struct {
	ctx              context.Context
	clientset        k8sClient.Clientset
	buildEndpointSem *semaphore.Weighted
	l7Proxy          *proxy.Proxy
	svc              *service.Service
	rec              *recorder.Recorder
	policy           *policy.Repository
	policyUpdater    *policy.Updater
	preFilter        datapath.PreFilter

	statusCollectMutex lock.RWMutex
	statusResponse     models.StatusResponse
	statusCollector    *status.Collector

	monitorAgent monitoragent.Agent
	ciliumHealth *health.CiliumHealth

	deviceManager *linuxdatapath.DeviceManager

	// dnsNameManager tracks which api.FQDNSelector are present in policy which
	// apply to locally running endpoints.
	dnsNameManager *fqdn.NameManager

	// dnsProxyContext contains fields relevant to the DNS proxy. See each
	// field's godoc for more details.
	dnsProxyContext dnsProxyContext

	// Used to synchronize generation of daemon's BPF programs and endpoint BPF
	// programs.
	compilationMutex *lock.RWMutex

	// prefixLengths tracks a mapping from CIDR prefix length to the count
	// of rules that refer to that prefix length.
	prefixLengths *counter.PrefixLengthCounter

	clustermesh *clustermesh.ClusterMesh

	mtuConfig mtu.Configuration

	datapathRegenTrigger *trigger.Trigger

	// datapath is the underlying datapath implementation to use to
	// implement all aspects of an agent
	datapath datapath.Datapath

	// nodeDiscovery defines the node discovery logic of the agent
	nodeDiscovery  *nodediscovery.NodeDiscovery
	nodeLocalStore *node.LocalNodeStore

	// ipam is the IP address manager of the agent
	ipam *ipam.IPAM

	endpointManager endpointmanager.EndpointManager

	identityAllocator CachingIdentityAllocator

	ipcache *ipcache.IPCache

	k8sWatcher *watchers.K8sWatcher

	// endpointMetadataFetcher knows how to fetch Kubernetes metadata for endpoints.
	endpointMetadataFetcher endpointMetadataFetcher

	// healthEndpointRouting is the information required to set up the health
	// endpoint's routing in ENI or Azure IPAM mode
	healthEndpointRouting *linuxrouting.RoutingInfo

	linkCache      *link.LinkCache
	hubbleObserver atomic.Pointer[observer.LocalObserverServer]

	// endpointCreations is a map of all currently ongoing endpoint
	// creation events
	endpointCreations *endpointCreationManager

	redirectPolicyManager *redirectpolicy.Manager

	bgpSpeaker *speaker.MetalLBSpeaker

	egressGatewayManager *egressgateway.Manager

	cgroupManager *manager.CgroupManager

	ipamMetadata *ipamMetadata.Manager

	apiLimiterSet *rate.APILimiterSet

	// event queue for serializing configuration updates to the daemon.
	configModifyQueue *eventqueue.EventQueue

	// controller for Cilium's BGP control plane.
	bgpControlPlaneController *bgpv1.Controller

	// CIDRs for which identities were restored during bootstrap
	restoredCIDRs []netip.Prefix

	// Controllers owned by the daemon
	controllers *controller.Manager

	// BIG-TCP config values
	bigTCPConfig bigtcp.Configuration

	// just used to tie together some status reporting
	cniConfigManager cni.CNIConfigManager

	l2announcer *l2announcer.L2Announcer

	// authManager for reporting the status of the auth system certificate provider
	authManager *auth.AuthManager

	// read-only map of all the hive settings
	settings cellSettings
	// enable modules health support
	healthProvider cell.Health
	healthReporter cell.HealthReporter
}

func (d *Daemon) initDNSProxyContext(size int) {
	d.dnsProxyContext = dnsProxyContext{
		responseMutexes: make([]*lock.Mutex, size),
		modulus:         big.NewInt(int64(size)),
	}
	for i := range d.dnsProxyContext.responseMutexes {
		d.dnsProxyContext.responseMutexes[i] = new(lock.Mutex)
	}
}

// dnsProxyContext is a meta struct containing fields relevant to the DNS proxy
// of the daemon, for organizational purposes.
type dnsProxyContext struct {
	// responseMutexes is used to serialized the critical path of
	// notifyOnDNSMsg() to ensure that identity allocation and ipcache
	// insertion happen atomically between parallel DNS request handling.
	responseMutexes []*lock.Mutex
	// modulus is used when computing the hash of the DNS response IPs in order
	// to map them to the mutexes inside responseMutexes.
	modulus *big.Int
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

// GetCompilationLock returns the mutex responsible for synchronizing compilation
// of BPF programs.
func (d *Daemon) GetCompilationLock() *lock.RWMutex {
	return d.compilationMutex
}

func (d *Daemon) init() error {
	globalsDir := option.Config.GetGlobalsDir()
	if err := os.MkdirAll(globalsDir, defaults.RuntimePathRights); err != nil {
		log.WithError(err).WithField(logfields.Path, globalsDir).Fatal("Could not create runtime directory")
	}

	if err := os.Chdir(option.Config.StateDir); err != nil {
		log.WithError(err).WithField(logfields.Path, option.Config.StateDir).Fatal("Could not change to runtime directory")
	}

	if !option.Config.DryMode {
		bandwidth.InitBandwidthManager()

		if err := d.Datapath().Loader().Reinitialize(d.ctx, d, d.mtuConfig.GetDeviceMTU(), d.Datapath(), d.l7Proxy); err != nil {
			return fmt.Errorf("failed while reinitializing datapath: %w", err)
		}

		if option.Config.EnableL7Proxy {
			if err := linuxdatapath.NodeEnsureLocalRoutingRule(); err != nil {
				return fmt.Errorf("ensuring local routing rule: %w", err)
			}
		}
	}

	return nil
}

// createPrefixLengthCounter wraps around the counter library, providing
// references to prefix lengths that will always be present.
func createPrefixLengthCounter() *counter.PrefixLengthCounter {
	max6, max4 := ipcachemap.IPCacheMap().GetMaxPrefixLengths()
	return counter.DefaultPrefixLengthCounter(max6, max4)
}

// restoreCiliumHostIPs completes the `cilium_host` IP restoration process
// (part 2/2). This function is called after fully syncing with K8s to ensure
// that the most up-to-date information has been retrieved. At this point, the
// daemon is aware of all the necessary information to restore the appropriate
// IP.
func (d *Daemon) restoreCiliumHostIPs(ipv6 bool, fromK8s net.IP) error {
	var (
		cidrs  []*cidr.CIDR
		fromFS net.IP
	)

	if ipv6 {
		switch option.Config.IPAMMode() {
		case ipamOption.IPAMCRD:
			// The native routing CIDR is the pod CIDR in these IPAM modes.
			cidrs = []*cidr.CIDR{option.Config.GetIPv6NativeRoutingCIDR()}
		default:
			cidrs = []*cidr.CIDR{node.GetIPv6AllocRange()}
		}
		fromFS = node.GetIPv6Router()
	} else {
		switch option.Config.IPAMMode() {
		case ipamOption.IPAMCRD:
			// The native routing CIDR is the pod CIDR in CRD mode.
			cidrs = []*cidr.CIDR{option.Config.GetIPv4NativeRoutingCIDR()}
		case ipamOption.IPAMENI, ipamOption.IPAMAzure, ipamOption.IPAMAlibabaCloud:
			// d.startIPAM() has already been called at this stage to initialize sharedNodeStore with ownNode info
			// needed for GetVpcCIDRs()
			cidrs = d.ipam.GetVpcCIDRs()
		default:
			cidrs = []*cidr.CIDR{node.GetIPv4AllocRange()}
		}
		fromFS = node.GetInternalIPv4Router()
	}

	restoredIP := node.RestoreHostIPs(ipv6, fromK8s, fromFS, cidrs)
	return removeOldRouterState(ipv6, restoredIP)
}

// removeOldRouterState will try to ensure that the only IP assigned to the
// `cilium_host` interface is the given restored IP. If the given IP is nil,
// then it attempts to clear all IPs from the interface.
func removeOldRouterState(ipv6 bool, restoredIP net.IP) error {
	l, err := netlink.LinkByName(defaults.HostDevice)
	if errors.As(err, &netlink.LinkNotFoundError{}) && restoredIP == nil {
		// There's no old state remove as the host device doesn't exist and
		// there's no restored IP anyway.
		return nil
	}
	if err != nil {
		return resiliency.Retryable(err)
	}

	family := netlink.FAMILY_V4
	if ipv6 {
		family = netlink.FAMILY_V6
	}
	addrs, err := netlink.AddrList(l, family)
	if err != nil {
		return resiliency.Retryable(err)
	}

	isRestoredIP := func(a netlink.Addr) bool {
		return restoredIP != nil && restoredIP.Equal(a.IP)
	}
	if len(addrs) == 0 || (len(addrs) == 1 && isRestoredIP(addrs[0])) {
		return nil // nothing to clean up
	}

	log.Info("More than one stale router IP was found on the cilium_host device after restoration, cleaning up old router IPs.")

	for _, a := range addrs {
		if isRestoredIP(a) {
			continue
		}
		if e := netlink.AddrDel(l, &a); e != nil {
			err = errors.Join(err, resiliency.Retryable(fmt.Errorf("failed to remove IP %s: %w", a.IP, e)))
		}
	}

	return err
}

// newDaemon creates and returns a new Daemon with the parameters set in c.
func newDaemon(ctx context.Context, cleaner *daemonCleanup, params *daemonParams) (*Daemon, *endpointRestoreState, error) {
	var err error

	bootstrapStats.daemonInit.Start()

	// Validate configuration options that depend on other cells.
	if option.Config.IdentityAllocationMode == option.IdentityAllocationModeCRD && !params.Clientset.IsEnabled() &&
		option.Config.DatapathMode != datapathOption.DatapathModeLBOnly {
		return nil, nil, fmt.Errorf("CRD Identity allocation mode requires k8s to be configured")
	}

	// Check the kernel if we can make use of managed neighbor entries which
	// simplifies and fully 'offloads' L2 resolution handling to the kernel.
	if !option.Config.DryMode {
		if err := probes.HaveManagedNeighbors(); err == nil {
			log.Info("Using Managed Neighbor Kernel support")
			option.Config.ARPPingKernelManaged = true
		}
	}

	// Do the partial kube-proxy replacement initialization before creating BPF
	// maps. Otherwise, some maps might not be created (e.g. session affinity).
	// finishKubeProxyReplacementInit(), which is called later after the device
	// detection, might disable BPF NodePort and friends. But this is fine, as
	// the feature does not influence the decision which BPF maps should be
	// created.
	if err := initKubeProxyReplacementOptions(); err != nil {
		log.WithError(err).Error("unable to initialize kube-proxy replacement options")
		return nil, nil, fmt.Errorf("unable to initialize kube-proxy replacement options: %w", err)
	}

	ctmap.InitMapInfo(option.Config.EnableIPv4, option.Config.EnableIPv6, option.Config.EnableNodePort)
	policymap.InitMapInfo(option.Config.PolicyMapEntries)

	lbmapInitParams := lbmap.InitParams{
		IPv4: option.Config.EnableIPv4,
		IPv6: option.Config.EnableIPv6,

		MaxSockRevNatMapEntries:  option.Config.SockRevNatEntries,
		ServiceMapMaxEntries:     option.Config.LBMapEntries,
		BackEndMapMaxEntries:     option.Config.LBMapEntries,
		RevNatMapMaxEntries:      option.Config.LBMapEntries,
		AffinityMapMaxEntries:    option.Config.LBMapEntries,
		SourceRangeMapMaxEntries: option.Config.LBMapEntries,
		MaglevMapMaxEntries:      option.Config.LBMapEntries,
	}
	if option.Config.LBServiceMapEntries > 0 {
		lbmapInitParams.ServiceMapMaxEntries = option.Config.LBServiceMapEntries
	}
	if option.Config.LBBackendMapEntries > 0 {
		lbmapInitParams.BackEndMapMaxEntries = option.Config.LBBackendMapEntries
	}
	if option.Config.LBRevNatEntries > 0 {
		lbmapInitParams.RevNatMapMaxEntries = option.Config.LBRevNatEntries
	}
	if option.Config.LBAffinityMapEntries > 0 {
		lbmapInitParams.AffinityMapMaxEntries = option.Config.LBAffinityMapEntries
	}
	if option.Config.LBSourceRangeMapEntries > 0 {
		lbmapInitParams.SourceRangeMapMaxEntries = option.Config.LBSourceRangeMapEntries
	}
	if option.Config.LBMaglevMapEntries > 0 {
		lbmapInitParams.MaglevMapMaxEntries = option.Config.LBMaglevMapEntries
	}
	lbmap.Init(lbmapInitParams)

	authKeySize, encryptKeyID, err := setupIPSec()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to setup encryption: %s", err)
	}

	var mtuConfig mtu.Configuration
	externalIP := node.GetIPv4()
	if externalIP == nil {
		externalIP = node.GetIPv6()
	}
	configuredMTU := option.Config.MTU
	if mtu := params.CNIConfigManager.GetMTU(); mtu > 0 {
		configuredMTU = mtu
		log.WithField("mtu", configuredMTU).Info("Overwriting MTU based on CNI configuration")
	}
	// ExternalIP could be nil but we are covering that case inside NewConfiguration
	mtuConfig = mtu.NewConfiguration(
		authKeySize,
		option.Config.EnableIPSec,
		option.Config.TunnelExists(),
		option.Config.EnableWireguard,
		option.Config.EnableHighScaleIPcache && option.Config.EnableNodePort,
		configuredMTU,
		externalIP,
	)

	params.NodeManager.Subscribe(params.Datapath.Node())

	identity.IterateReservedIdentities(func(_ identity.NumericIdentity, _ *identity.Identity) {
		metrics.Identity.WithLabelValues(identity.ReservedIdentityType).Inc()
	})
	if option.Config.EnableWellKnownIdentities {
		// Must be done before calling policy.NewPolicyRepository() below.
		num := identity.InitWellKnownIdentities(option.Config, params.ClusterInfo)
		metrics.Identity.WithLabelValues(identity.WellKnownIdentityType).Add(float64(num))
	}

	nd := nodediscovery.NewNodeDiscovery(params.NodeManager, params.Clientset, mtuConfig, params.CNIConfigManager.GetCustomNetConf())

	d := Daemon{
		ctx:               ctx,
		clientset:         params.Clientset,
		prefixLengths:     createPrefixLengthCounter(),
		buildEndpointSem:  semaphore.NewWeighted(int64(numWorkerThreads())),
		compilationMutex:  new(lock.RWMutex),
		mtuConfig:         mtuConfig,
		datapath:          params.Datapath,
		deviceManager:     params.DeviceManager,
		nodeDiscovery:     nd,
		nodeLocalStore:    params.LocalNodeStore,
		endpointCreations: newEndpointCreationManager(params.Clientset),
		apiLimiterSet:     params.APILimiterSet,
		controllers:       controller.NewManager(),
		// **NOTE** The global identity allocator is not yet initialized here; that
		// happens below via InitIdentityAllocator(). Only the local identity
		// allocator is initialized here.
		identityAllocator:    params.IdentityAllocator,
		ipcache:              params.IPCache,
		policy:               params.Policy,
		policyUpdater:        params.PolicyUpdater,
		egressGatewayManager: params.EgressGatewayManager,
		ipamMetadata:         params.IPAMMetadataManager,
		cniConfigManager:     params.CNIConfigManager,
		clustermesh:          params.ClusterMesh,
		monitorAgent:         params.MonitorAgent,
		l2announcer:          params.L2Announcer,
		l7Proxy:              params.L7Proxy,
		authManager:          params.AuthManager,
		settings:             params.Settings,
		healthProvider:       params.HealthProvider,
		healthReporter:       params.HealthReporter,
	}

	d.configModifyQueue = eventqueue.NewEventQueueBuffered("config-modify-queue", ConfigModifyQueueSize)
	d.configModifyQueue.Run()

	d.rec, err = recorder.NewRecorder(d.ctx, &d)
	if err != nil {
		log.WithError(err).Error("error while initializing BPF pcap recorder")
		return nil, nil, fmt.Errorf("error while initializing BPF pcap recorder: %w", err)
	}

	// Collect old CIDR identities
	var oldNIDs []identity.NumericIdentity
	var oldIngressIPs []netip.Prefix
	if option.Config.RestoreState && !option.Config.DryMode {
		if err := ipcachemap.IPCacheMap().DumpWithCallback(func(key bpf.MapKey, value bpf.MapValue) {
			k := key.(*ipcachemap.Key)
			v := value.(*ipcachemap.RemoteEndpointInfo)
			nid := identity.NumericIdentity(v.SecurityIdentity)
			if scope := nid.Scope(); scope == identity.IdentityScopeLocal ||
				(scope == identity.IdentityScopeRemoteNode && option.Config.PolicyCIDRMatchesNodes()) {
				d.restoredCIDRs = append(d.restoredCIDRs, k.Prefix())
				oldNIDs = append(oldNIDs, nid)
			} else if nid == identity.ReservedIdentityIngress && v.TunnelEndpoint.IsZero() {
				prefix := k.Prefix()
				oldIngressIPs = append(oldIngressIPs, prefix)
				addr := prefix.Addr()
				if addr.Is4() {
					node.SetIngressIPv4(addr.AsSlice())
				} else {
					node.SetIngressIPv6(addr.AsSlice())
				}
			}
		}); err != nil && !os.IsNotExist(err) {
			log.WithError(err).Debug("Error dumping ipcache")
		}
		// DumpWithCallback() leaves the ipcache map open, must close before opened for
		// parallel mode in Daemon.initMaps()
		ipcachemap.IPCacheMap().Close()
	}

	if err := d.initPolicy(); err != nil {
		return nil, nil, fmt.Errorf("error while initializing policy subsystem: %w", err)
	}

	// Preallocate IDs for old CIDRs. This must be done before any Identity allocations are
	// possible so that the old IDs are still available. That is why we do this ASAP after the
	// new (userspace) ipcache is created above.
	//
	// CIDRs were dumped from the old ipcache, they are re-allocated here, hopefully with the
	// same numeric IDs as before, but the restored identities are to be upsterted to the new
	// (datapath) ipcache after it has been initialized below. This is accomplished by passing
	// 'restoredCIDRidentities' to AllocateCIDRs() and then calling
	// UpsertGeneratedIdentities(restoredCIDRidentities) after initMaps() below.
	restoredCIDRidentities := make(map[netip.Prefix]*identity.Identity)
	if len(d.restoredCIDRs) > 0 {
		log.Infof("Restoring %d old CIDR identities", len(d.restoredCIDRs))
		_, err = d.ipcache.AllocateCIDRs(d.restoredCIDRs, oldNIDs, restoredCIDRidentities)
		if err != nil {
			log.WithError(err).Error("Error allocating old CIDR identities")
		}
		// Log a warning for the first CIDR identity than could not be restored with the
		// same numeric identity as before the restart. This can only happen if we have
		// re-introduced bugs into this agent bootstrap order, so we want to surface this.
		for i, prefix := range d.restoredCIDRs {
			id, exists := restoredCIDRidentities[prefix]
			if !exists || id.ID != oldNIDs[i] {
				log.WithField(logfields.Identity, oldNIDs[i]).Warn("Could not restore all CIDR identities")
				break
			}
		}
	}

	d.endpointManager = params.EndpointManager

	d.svc = service.NewService(&d, d.l7Proxy, d.datapath.LBMap())

	d.redirectPolicyManager = redirectpolicy.NewRedirectPolicyManager(d.svc, params.Resources.LocalPods)
	if option.Config.BGPAnnounceLBIP || option.Config.BGPAnnouncePodCIDR {
		log.WithField("url", "https://github.com/cilium/cilium/issues/22246").
			Warn("You are using the legacy BGP feature, which will only receive security updates and bugfixes. " +
				"It is recommended to migrate to the BGP Control Plane feature if possible, which has better support.")

		d.bgpSpeaker, err = speaker.New(ctx, params.Clientset, speaker.Opts{
			LoadBalancerIP: option.Config.BGPAnnounceLBIP,
			PodCIDR:        option.Config.BGPAnnouncePodCIDR,
		})
		if err != nil {
			log.WithError(err).Error("Error creating new BGP speaker")
			return nil, nil, err
		}
	}

	d.cgroupManager = manager.NewCgroupManager()

	d.k8sWatcher = watchers.NewK8sWatcher(
		params.Clientset,
		d.endpointManager,
		d.nodeDiscovery,
		&d,
		d.policy,
		d.svc,
		d.datapath,
		d.redirectPolicyManager,
		d.bgpSpeaker,
		d.l7Proxy,
		option.Config,
		d.ipcache,
		d.cgroupManager,
		params.Resources,
		params.ServiceCache,
	)
	nd.RegisterK8sGetters(d.k8sWatcher)

	d.k8sWatcher.RegisterNodeSubscriber(d.endpointManager)
	if option.Config.BGPAnnounceLBIP || option.Config.BGPAnnouncePodCIDR {
		switch option.Config.IPAMMode() {
		case ipamOption.IPAMKubernetes:
			d.bgpSpeaker.SubscribeToLocalNodeResource(ctx, params.Resources.LocalNode)
		case ipamOption.IPAMClusterPool:
			d.bgpSpeaker.SubscribeToLocalCiliumNodeResource(ctx, params.Resources.LocalCiliumNode)
		}
	}
	if option.Config.EnableServiceTopology {
		d.k8sWatcher.RegisterNodeSubscriber(d.k8sWatcher.K8sSvcCache)
	}

	// watchers.NewCiliumNodeUpdater needs to be registered *after* d.endpointManager
	d.k8sWatcher.RegisterNodeSubscriber(watchers.NewCiliumNodeUpdater(d.nodeDiscovery))

	d.redirectPolicyManager.RegisterSvcCache(d.k8sWatcher.K8sSvcCache)
	if option.Config.BGPAnnounceLBIP {
		d.bgpSpeaker.RegisterSvcCache(d.k8sWatcher.K8sSvcCache)
	}

	bootstrapStats.daemonInit.End(true)

	// Stop all endpoints (its goroutines) on exit.
	cleaner.cleanupFuncs.Add(func() {
		log.Info("Waiting for all endpoints' goroutines to be stopped.")
		var wg sync.WaitGroup

		eps := d.endpointManager.GetEndpoints()
		wg.Add(len(eps))

		for _, ep := range eps {
			go func(ep *endpoint.Endpoint) {
				ep.Stop()
				wg.Done()
			}(ep)
		}

		wg.Wait()
		log.Info("All endpoints' goroutines stopped.")
	})

	// Open or create BPF maps.
	bootstrapStats.mapsInit.Start()
	err = d.initMaps()
	bootstrapStats.mapsInit.EndError(err)
	if err != nil {
		log.WithError(err).Error("error while opening/creating BPF maps")
		return nil, nil, fmt.Errorf("error while opening/creating BPF maps: %w", err)
	}
	// Upsert restored CIDRs after the new ipcache has been opened above
	if len(restoredCIDRidentities) > 0 {
		d.ipcache.UpsertGeneratedIdentities(restoredCIDRidentities, nil)
	}
	// Upsert restored local Ingress IPs
	for _, ingressIP := range oldIngressIPs {
		d.ipcache.UpsertLabels(
			ingressIP,
			labels.LabelIngress,
			source.Restored,
			ipcachetypes.NewResourceID(ipcachetypes.ResourceKindDaemon, "", ""),
		)
	}
	if len(oldIngressIPs) > 0 {
		log.WithField(logfields.Ingress, oldIngressIPs).Info("Restored ingress IPs")
	}

	// Read the service IDs of existing services from the BPF map and
	// reserve them. This must be done *before* connecting to the
	// Kubernetes apiserver and serving the API to ensure service IDs are
	// not changing across restarts or that a new service could accidentally
	// use an existing service ID.
	// Also, create missing v2 services from the corresponding legacy ones.
	if option.Config.RestoreState && !option.Config.DryMode {
		bootstrapStats.restore.Start()
		if err := d.svc.RestoreServices(); err != nil {
			log.WithError(err).Warn("Failed to restore services from BPF maps")
		}
		bootstrapStats.restore.End(true)
	}

	debug.RegisterStatusObject("k8s-service-cache", d.k8sWatcher.K8sSvcCache)
	debug.RegisterStatusObject("ipam", d.ipam)
	debug.RegisterStatusObject("ongoing-endpoint-creations", d.endpointCreations)

	d.k8sWatcher.RunK8sServiceHandler()

	if option.Config.DNSPolicyUnloadOnShutdown {
		log.Debugf("Registering cleanup function to unload DNS policies due to --%s", option.DNSPolicyUnloadOnShutdown)

		// add to pre-cleanup funcs because this needs to run on graceful shutdown, but
		// before the relevant subystems are being shut down.
		cleaner.preCleanupFuncs.Add(func() {
			// Stop k8s watchers
			log.Info("Stopping k8s service handler")
			d.k8sWatcher.StopK8sServiceHandler()

			// Iterate over the policy repository and remove L7 DNS part
			needsPolicyRegen := false
			removeL7DNSRules := func(pr policyAPI.Ports) error {
				portProtocols := pr.GetPortProtocols()
				if len(portProtocols) == 0 {
					return nil
				}
				portRule := pr.GetPortRule()
				if portRule == nil || portRule.Rules == nil {
					return nil
				}
				dnsRules := portRule.Rules.DNS
				log.Debugf("Found egress L7 DNS rules (portProtocol %#v): %#v", portProtocols[0], dnsRules)

				// For security reasons, the L7 DNS policy must be a
				// wildcard in order to trigger this logic.
				// Otherwise we could invalidate the L7 security
				// rules. This means if any of the DNS L7 rules
				// have a matchPattern of * then it is OK to delete
				// the L7 portion of those rules.
				hasWildcard := false
				for _, dns := range dnsRules {
					if dns.MatchPattern == "*" {
						hasWildcard = true
						break
					}
				}
				if hasWildcard {
					portRule.Rules = nil
					needsPolicyRegen = true
				}
				return nil
			}

			policyRepo := d.GetPolicyRepository()
			policyRepo.Iterate(func(rule *policyAPI.Rule) {
				for _, er := range rule.Egress {
					_ = er.ToPorts.Iterate(removeL7DNSRules)
				}
			})

			if !needsPolicyRegen {
				log.Infof("No policy recalculation needed to remove DNS rules due to --%s", option.DNSPolicyUnloadOnShutdown)
				return
			}

			// Bump revision to trigger policy recalculation
			log.Infof("Triggering policy recalculation to remove DNS rules due to --%s", option.DNSPolicyUnloadOnShutdown)
			policyRepo.BumpRevision()
			regenerationMetadata := &regeneration.ExternalRegenerationMetadata{
				Reason:            "unloading DNS rules on graceful shutdown",
				RegenerationLevel: regeneration.RegenerateWithoutDatapath,
			}
			wg := d.endpointManager.RegenerateAllEndpoints(regenerationMetadata)
			wg.Wait()
			log.Info("All endpoints regenerated after unloading DNS rules on graceful shutdown")
		})
	}

	treatRemoteNodeAsHost := option.Config.AlwaysAllowLocalhost() && !option.Config.EnableRemoteNodeIdentity
	policyAPI.InitEntities(params.ClusterInfo.Name, treatRemoteNodeAsHost)

	bootstrapStats.restore.Start()
	// fetch old endpoints before k8s is configured.
	restoredEndpoints, err := d.fetchOldEndpoints(option.Config.StateDir)
	if err != nil {
		log.WithError(err).Error("Unable to read existing endpoints")
	}
	bootstrapStats.restore.End(true)

	bootstrapStats.fqdn.Start()
	err = d.bootstrapFQDN(restoredEndpoints.possible, option.Config.ToFQDNsPreCache)
	if err != nil {
		bootstrapStats.fqdn.EndError(err)
		return nil, restoredEndpoints, err
	}
	if proxy.DefaultDNSProxy != nil {
		// This is done in preCleanup so that proxy stops serving DNS traffic before shutdown
		cleaner.preCleanupFuncs.Add(func() {
			proxy.DefaultDNSProxy.Cleanup()
		})
	}

	bootstrapStats.fqdn.End(true)

	if params.Clientset.IsEnabled() {
		bootstrapStats.k8sInit.Start()
		// Errors are handled inside WaitForCRDsToRegister. It will fatal on a
		// context deadline or if the context has been cancelled, the context's
		// error will be returned. Otherwise, it succeeded.
		if !option.Config.DryMode {
			if err := d.k8sWatcher.WaitForCRDsToRegister(d.ctx); err != nil {
				return nil, restoredEndpoints, err
			}
		}

		// Launch the K8s node watcher so we can start receiving node events.
		// Launching the k8s node watcher at this stage will prevent all agents
		// from performing Gets directly into kube-apiserver to get the most up
		// to date version of the k8s node. This allows for better scalability
		// in large clusters.
		d.k8sWatcher.NodesInit(d.clientset)

		if option.Config.IPAM == ipamOption.IPAMClusterPool ||
			option.Config.IPAM == ipamOption.IPAMMultiPool {
			// Create the CiliumNode custom resource. This call will block until
			// the custom resource has been created
			d.nodeDiscovery.UpdateCiliumNodeResource()
		}

		if err := k8s.WaitForNodeInformation(d.ctx, d.k8sWatcher); err != nil {
			log.WithError(err).Error("unable to connect to get node spec from apiserver")
			return nil, nil, fmt.Errorf("unable to connect to get node spec from apiserver: %w", err)
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

	if params.WGAgent != nil && option.Config.EnableWireguard {
		if err := params.WGAgent.Init(d.ipcache, d.mtuConfig); err != nil {
			log.WithError(err).Error("failed to initialize WireGuard agent")
			return nil, nil, fmt.Errorf("failed to initialize WireGuard agent: %w", err)
		}

		params.NodeManager.Subscribe(params.WGAgent)
	}

	// Perform an early probe on the underlying kernel on whether BandwidthManager
	// can be supported or not. This needs to be done before handleNativeDevices()
	// as BandwidthManager needs these to be available for setup.
	bandwidth.ProbeBandwidthManager()

	// The kube-proxy replacement and host-fw devices detection should happen after
	// establishing a connection to kube-apiserver, but before starting a k8s watcher.
	// This is because the device detection requires self (Cilium)Node object,
	// and the k8s service watcher depends on option.Config.EnableNodePort flag
	// which can be modified after the device detection.
	var devices []string
	if d.deviceManager != nil {
		if detected, err := d.deviceManager.Detect(params.Clientset.IsEnabled()); err == nil {
			devices = append(devices, detected...)
		} else {
			if option.Config.AreDevicesRequired() {
				// Fail hard if devices are required to function.
				return nil, nil, fmt.Errorf("failed to detect devices: %w", err)
			}
			log.WithError(err).Warn("failed to detect devices, disabling BPF NodePort")
			disableNodePort()
		}
	}

	if d.l2announcer != nil {
		d.l2announcer.DevicesChanged(devices)
	}

	if err := finishKubeProxyReplacementInit(); err != nil {
		log.WithError(err).Error("failed to finalise LB initialization")
		return nil, nil, fmt.Errorf("failed to finalise LB initialization: %w", err)
	}

	// BPF masquerade depends on BPF NodePort and require socket-LB to
	// be enabled in the tunneling mode, so the following checks should
	// happen after invoking initKubeProxyReplacementOptions().
	if option.Config.MasqueradingEnabled() && option.Config.EnableBPFMasquerade {

		var err error
		switch {
		case !option.Config.EnableNodePort:
			err = fmt.Errorf("BPF masquerade requires NodePort (--%s=\"true\")",
				option.EnableNodePort)
		case !option.Config.EnableRemoteNodeIdentity:
			err = fmt.Errorf("BPF masquerade requires remote node identities (--%s=\"true\")",
				option.EnableRemoteNodeIdentity)
		case len(option.Config.MasqueradeInterfaces) > 0:
			err = fmt.Errorf("BPF masquerade does not allow to specify devices via --%s (use --%s instead)",
				option.MasqueradeInterfaces, option.Devices)
		case option.Config.TunnelingEnabled() && !option.Config.EnableSocketLB:
			err = fmt.Errorf("BPF masquerade requires socket-LB (--%s=\"false\")",
				option.EnableSocketLB)
		}
		// ipt.InstallRules() (called by Reinitialize()) happens later than
		// this  statement, so it's OK to fallback to iptables-based MASQ.
		if err != nil {
			option.Config.EnableBPFMasquerade = false
			log.WithError(err).Warn("Falling back to iptables-based masquerading.")
			// Too bad, if we need to revert to iptables-based MASQ, we also cannot
			// use BPF host routing since we need the upper stack.
			if !option.Config.EnableHostLegacyRouting {
				option.Config.EnableHostLegacyRouting = true
				log.Infof("BPF masquerade could not be enabled. Falling back to legacy host routing (--%s=\"true\").",
					option.EnableHostLegacyRouting)
			}
		}
	}

	if option.Config.MasqueradingEnabled() && option.Config.EnableBPFMasquerade {
		if option.Config.EnableMasqueradeRouteSource {
			log.Error("BPF masquerading does not yet support masquerading to source IP from routing layer")
			return nil, nil, fmt.Errorf("BPF masquerading to route source (--%s=\"true\") currently not supported with BPF-based masquerading (--%s=\"true\")", option.EnableMasqueradeRouteSource, option.EnableBPFMasquerade)
		}
		// TODO(brb) nodeport constraints will be lifted once the SNAT BPF code has been refactored
		if err := node.InitBPFMasqueradeAddrs(option.Config.GetDevices()); err != nil {
			log.WithError(err).Error("failed to determine BPF masquerade addrs")
			return nil, nil, fmt.Errorf("failed to determine BPF masquerade addrs: %w", err)
		}
	} else if option.Config.EnableIPMasqAgent {
		log.WithError(err).Errorf("BPF ip-masq-agent requires (--%s=\"true\" or --%s=\"true\") and --%s=\"true\"", option.EnableIPv4Masquerade, option.EnableIPv6Masquerade, option.EnableBPFMasquerade)
		return nil, nil, fmt.Errorf("BPF ip-masq-agent requires (--%s=\"true\" or --%s=\"true\") and --%s=\"true\"", option.EnableIPv4Masquerade, option.EnableIPv6Masquerade, option.EnableBPFMasquerade)
	} else if !option.Config.MasqueradingEnabled() && option.Config.EnableBPFMasquerade {
		log.Infof("Auto-disabling %q feature since IPv4 and IPv6 masquerading are disabled",
			option.EnableBPFMasquerade)
		option.Config.EnableBPFMasquerade = false
	}
	if len(option.Config.GetDevices()) == 0 {
		if option.Config.EnableHostFirewall {
			msg := "Host firewall's external facing device could not be determined. Use --%s to specify."
			log.WithError(err).Errorf(msg, option.Devices)
			return nil, nil, fmt.Errorf(msg, option.Devices)
		}
		if option.Config.EnableHighScaleIPcache {
			msg := "External facing device for high-scale IPcache could not be determined. Use --%s to specify."
			log.WithError(err).Errorf(msg, option.Devices)
			return nil, nil, fmt.Errorf(msg, option.Devices)
		}
	}
	if option.Config.EnableSCTP {
		if probes.HaveLargeInstructionLimit() != nil {
			log.WithError(err).Error("SCTP support needs kernel 5.2 or newer")
			return nil, nil, fmt.Errorf("SCTP support needs kernel 5.2 or newer")
		}
	}

	bigtcp.InitBIGTCP(&d.bigTCPConfig)

	// Some of the k8s watchers rely on option flags set above (specifically
	// EnableBPFMasquerade), so we should only start them once the flag values
	// are set.
	if params.Clientset.IsEnabled() {
		bootstrapStats.k8sInit.Start()

		// Launch the K8s watchers in parallel as we continue to process other
		// daemon options.
		d.k8sWatcher.InitK8sSubsystem(d.ctx, params.CacheStatus)
		bootstrapStats.k8sInit.End(true)
	} else {
		close(params.CacheStatus)
	}

	bootstrapStats.cleanup.Start()
	err = clearCiliumVeths()
	bootstrapStats.cleanup.EndError(err)
	if err != nil {
		log.WithError(err).Warning("Unable to clean stale endpoint interfaces")
	}

	// Must init kvstore before starting node discovery
	if option.Config.KVStore == "" {
		log.Info("Skipping kvstore configuration")
	} else {
		bootstrapStats.kvstore.Start()
		d.initKVStore()
		bootstrapStats.kvstore.End(true)
	}

	// Fetch the router (`cilium_host`) IPs in case they were set a priori from
	// the Kubernetes or CiliumNode resource in the K8s subsystem from call
	// k8s.WaitForNodeInformation(). These will be used later after starting
	// IPAM initialization to finish off the `cilium_host` IP restoration (part
	// 2/2).
	router4FromK8s, router6FromK8s := node.GetInternalIPv4Router(), node.GetIPv6Router()

	// Configure IPAM without using the configuration yet.
	d.configureIPAM()

	if option.Config.JoinCluster {
		if params.Clientset.IsEnabled() {
			log.WithError(err).Errorf("cannot join a Cilium cluster (--%s) when configured as a Kubernetes node", option.JoinClusterName)
			return nil, nil, fmt.Errorf("cannot join a Cilium cluster (--%s) when configured as a Kubernetes node", option.JoinClusterName)
		}
		if option.Config.KVStore == "" {
			log.WithError(err).Errorf("joining a Cilium cluster (--%s) requires kvstore (--%s) be set", option.JoinClusterName, option.KVStore)
			return nil, nil, fmt.Errorf("joining a Cilium cluster (--%s) requires kvstore (--%s) be set", option.JoinClusterName, option.KVStore)
		}
		agentLabels := labels.NewLabelsFromModel(option.Config.AgentLabels).K8sStringMap()
		if option.Config.K8sNamespace != "" {
			agentLabels[k8sConst.PodNamespaceLabel] = option.Config.K8sNamespace
		}
		agentLabels[k8sConst.PodNameLabel] = nodeTypes.GetName()
		agentLabels[k8sConst.PolicyLabelCluster] = option.Config.ClusterName
		// Set configured agent labels to local node for node registration
		node.SetLabels(agentLabels)

		// This can override node addressing config, so do this before starting IPAM
		log.WithField(logfields.NodeName, nodeTypes.GetName()).Debug("Calling JoinCluster()")
		if err := d.nodeDiscovery.JoinCluster(nodeTypes.GetName()); err != nil {
			return nil, nil, err
		}

		// Start services watcher
		serviceStore.JoinClusterServices(d.k8sWatcher.K8sSvcCache, option.Config.ClusterName)
	}

	// Start IPAM
	d.startIPAM(params.Resources.LocalCiliumNode)
	// After the IPAM is started, in particular IPAM modes (CRD, ENI, Alibaba)
	// which use the VPC CIDR as the pod CIDR, we must attempt restoring the
	// router IPs from the K8s resources if we weren't able to restore them
	// from the fs. We must do this after IPAM because we must wait until the
	// K8s resources have been synced. Part 2/2 of restoration.
	gcHostIPsFn := func(ctx context.Context, retries int) (done bool, err error) {
		var errs error
		if option.Config.EnableIPv4 {
			errs = errors.Join(errs, d.restoreCiliumHostIPs(false, router4FromK8s))
		}
		if option.Config.EnableIPv6 {
			errs = errors.Join(errs, d.restoreCiliumHostIPs(true, router6FromK8s))
		}
		if resiliency.IsRetryable(errs) {
			log.WithField(logfields.Attempt, retries).WithError(errs).Warnf("Failed to remove old router IPs from cilium_host.")
			return false, nil
		}
		return true, errs
	}
	if err := resiliency.Retry(ctx, 100*time.Millisecond, 3, gcHostIPsFn); err != nil {
		log.WithError(err).Error("Restore of the cilium_host ips failed. Manual intervention is required to remove all other old IPs.")
	}

	bootstrapStats.restore.Start()
	// restore endpoints before any IPs are allocated to avoid eventual IP
	// conflicts later on, otherwise any IP conflict will result in the
	// endpoint not being able to be restored.
	err = d.restoreOldEndpoints(restoredEndpoints, true)
	if err != nil {
		log.WithError(err).Error("Unable to restore existing endpoints")
	}
	bootstrapStats.restore.End(true)

	if err := d.allocateIPs(); err != nil { // will log errors/fatal internally
		return nil, nil, err
	}

	// allocateIPs got us the routerIP so now we can create ipsec endpoint
	// we must do this before publishing the router IP otherwise remote
	// nodes could pick up the IP and send us outer headers we do not yet
	// have xfrm rules for.
	if option.Config.EnableIPSec {
		if err := ipsec.Init(); err != nil {
			log.WithError(err).Error("IPSec init failed")
		}
	}

	// Must occur after d.allocateIPs(), see GH-14245 and its fix.
	d.nodeDiscovery.StartDiscovery()

	// Annotation of the k8s node must happen after discovery of the
	// PodCIDR range and allocation of the health IPs.
	if params.Clientset.IsEnabled() && option.Config.AnnotateK8sNode {
		bootstrapStats.k8sInit.Start()
		log.WithFields(logrus.Fields{
			logfields.V4Prefix:       node.GetIPv4AllocRange(),
			logfields.V6Prefix:       node.GetIPv6AllocRange(),
			logfields.V4HealthIP:     node.GetEndpointHealthIPv4(),
			logfields.V6HealthIP:     node.GetEndpointHealthIPv6(),
			logfields.V4IngressIP:    node.GetIngressIPv4(),
			logfields.V6IngressIP:    node.GetIngressIPv6(),
			logfields.V4CiliumHostIP: node.GetInternalIPv4Router(),
			logfields.V6CiliumHostIP: node.GetIPv6Router(),
		}).Info("Annotating k8s node")

		latestLocalNode, err := d.nodeLocalStore.Get(ctx)
		if err == nil {
			_, err = k8s.AnnotateNode(
				params.Clientset,
				nodeTypes.GetName(),
				latestLocalNode.Node,
				encryptKeyID)
		}
		if err != nil {
			log.WithError(err).Warning("Cannot annotate k8s node with CIDR range")
		}

		bootstrapStats.k8sInit.End(true)
	} else if !option.Config.AnnotateK8sNode {
		log.Debug("Annotate k8s node is disabled.")
	}

	// Trigger refresh and update custom resource in the apiserver with all restored endpoints.
	// Trigger after nodeDiscovery.StartDiscovery to avoid custom resource update conflict.
	if option.Config.EnableIPv6 {
		d.ipam.IPv6Allocator.RestoreFinished()
	}
	if option.Config.EnableIPv4 {
		d.ipam.IPv4Allocator.RestoreFinished()
	}

	if option.Config.DatapathMode != datapathOption.DatapathModeLBOnly {
		// This needs to be done after the node addressing has been configured
		// as the node address is required as suffix.
		// well known identities have already been initialized above.
		// Ignore the channel returned by this function, as we want the global
		// identity allocator to run asynchronously.
		realIdentityAllocator := d.identityAllocator
		realIdentityAllocator.InitIdentityAllocator(params.Clientset)
	}

	// Must be done at least after initializing BPF LB-related maps
	// (lbmap.Init()).
	bootstrapStats.bpfBase.Start()
	err = d.init()
	bootstrapStats.bpfBase.EndError(err)
	if err != nil {
		return nil, restoredEndpoints, fmt.Errorf("error while initializing daemon: %w", err)
	}

	// iptables rules can be updated only after d.init() intializes the iptables above.
	err = d.updateDNSDatapathRules(d.ctx)
	if err != nil {
		log.WithError(err).Error("error encountered while updating DNS datapath rules.")
		return nil, restoredEndpoints, fmt.Errorf("error encountered while updating DNS datapath rules: %w", err)
	}

	// Start the controller for periodic sync. The purpose of the
	// controller is to ensure that endpoints and host IPs entries are
	// reinserted to the bpf maps if they are ever removed from them.
	syncErrs := make(chan error, 1)
	var syncHostIPsControllerGroup = controller.NewGroup("sync-host-ips")
	d.controllers.UpdateController(
		syncHostIPsController,
		controller.ControllerParams{
			Group: syncHostIPsControllerGroup,
			DoFunc: func(ctx context.Context) error {
				err := d.syncHostIPs()
				select {
				case syncErrs <- err:
				default:
				}
				return err
			},
			RunInterval: time.Minute,
			Context:     d.ctx,
		})

	// Wait for the initial sync and check that it succeeded.
	if err := <-syncErrs; err != nil {
		return nil, nil, err
	}

	if err := loader.RestoreTemplates(option.Config.StateDir); err != nil {
		log.WithError(err).Error("Unable to restore previous BPF templates")
	}

	// Start watcher for endpoint IP --> identity mappings in key-value store.
	// this needs to be done *after* init() for the daemon in that function,
	// we populate the IPCache with the host's IP(s).
	d.ipcache.InitIPIdentityWatcher(d.ctx, params.StoreFactory)
	identitymanager.Subscribe(d.policy)

	// Start listening to changed devices if requested.
	if option.Config.EnableRuntimeDeviceDetection && d.deviceManager != nil {
		if option.Config.AreDevicesRequired() {
			devicesChan, err := d.deviceManager.Listen(ctx)
			if err != nil {
				log.WithError(err).Warn("Runtime device detection failed to start")
			}
			go func() {
				for devices := range devicesChan {
					d.ReloadOnDeviceChange(devices)
				}
			}()
		} else {
			log.Info("Runtime device detection requested, but no feature requires it. Disabling detection.")
		}
	}

	if option.Config.EnableIPSec {
		if err := ipsec.StartKeyfileWatcher(ctx, option.Config.IPSecKeyFile, nd, d.Datapath().Node()); err != nil {
			log.WithError(err).Error("Unable to start IPSec keyfile watcher")
		}

		ipsec.StartStaleKeysReclaimer(ctx)
	}

	return &d, restoredEndpoints, nil
}

// ReloadOnDeviceChange regenerates device related information and reloads the datapath.
// The devices is the new set of devices that replaces the old set.
func (d *Daemon) ReloadOnDeviceChange(devices []string) {
	option.Config.SetDevices(devices)

	if option.Config.MasqueradingEnabled() && option.Config.EnableBPFMasquerade {
		if err := node.InitBPFMasqueradeAddrs(devices); err != nil {
			log.Warnf("InitBPFMasqueradeAddrs failed: %s", err)
		}
	}

	if d.l2announcer != nil {
		d.l2announcer.DevicesChanged(devices)
	}

	if option.Config.EnableNodePort {
		if err := node.InitNodePortAddrs(devices, option.Config.LBDevInheritIPAddr); err != nil {
			log.WithError(err).Warn("Failed to initialize NodePort addresses")
		} else {
			// Synchronize services and endpoints to reflect new addresses onto lbmap.
			d.svc.SyncServicesOnDeviceChange(d.Datapath().LocalNodeAddressing())
			d.controllers.TriggerController(syncHostIPsController)
		}
	}

	// Reload the datapath.
	wg, err := d.TriggerReloadWithoutCompile("devices changed")
	if err != nil {
		log.WithError(err).Warn("Failed to reload datapath")
		return
	}
	wg.Wait()
}

// Close shuts down a daemon
func (d *Daemon) Close() {
	if d.datapathRegenTrigger != nil {
		d.datapathRegenTrigger.Shutdown()
	}
	identitymanager.RemoveAll()
	d.cgroupManager.Close()

	// Ensures all controllers are stopped!
	d.controllers.RemoveAllAndWait()
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
	if err := d.Datapath().Loader().Reinitialize(d.ctx, d, d.mtuConfig.GetDeviceMTU(), d.Datapath(), d.l7Proxy); err != nil {
		return nil, fmt.Errorf("unable to recompile base programs from %s: %s", reason, err)
	}

	regenRequest := &regeneration.ExternalRegenerationMetadata{
		Reason:            reason,
		RegenerationLevel: regeneration.RegenerateWithDatapathLoad,
	}
	return d.endpointManager.RegenerateAllEndpoints(regenRequest), nil
}

func (d *Daemon) datapathRegen(reasons []string) {
	reason := strings.Join(reasons, ", ")

	regenerationMetadata := &regeneration.ExternalRegenerationMetadata{
		Reason:            reason,
		RegenerationLevel: regeneration.RegenerateWithDatapathRewrite,
	}
	d.endpointManager.RegenerateAllEndpoints(regenerationMetadata)
}

// TriggerDatapathRegen triggers datapath rewrite for every daemon's endpoint.
// This is only called after agent configuration changes for now. Policy revision
// needs to be increased on PolicyEnforcement mode change.
func (d *Daemon) TriggerDatapathRegen(force bool, reason string) {
	if force {
		log.Debug("PolicyEnforcement mode changed, increasing policy revision to enforce policy recalculation")
		d.policy.BumpRevision()
	}
	d.datapathRegenTrigger.TriggerWithReason(reason)
}

func changedOption(key string, value option.OptionSetting, data interface{}) {
	d := data.(*Daemon)
	if key == option.Debug {
		// Set the debug toggle (this can be a no-op)
		if d.DebugEnabled() {
			logging.SetLogLevelToDebug()
		}
		// Reflect log level change to proxies
		// Might not be initialized yet
		if option.Config.EnableL7Proxy {
			d.l7Proxy.ChangeLogLevel(logging.GetLevel(logging.DefaultLogger))
		}
	}
	d.policy.BumpRevision() // force policy recalculation
}

// numWorkerThreads returns the number of worker threads with a minimum of 2.
func numWorkerThreads() int {
	ncpu := runtime.NumCPU()
	minWorkerThreads := 2

	if ncpu < minWorkerThreads {
		return minWorkerThreads
	}
	return ncpu
}

// SendNotification sends an agent notification to the monitor
func (d *Daemon) SendNotification(notification monitorAPI.AgentNotifyMessage) error {
	if option.Config.DryMode {
		return nil
	}
	return d.monitorAgent.SendEvent(monitorAPI.MessageTypeAgent, notification)
}

type endpointMetadataFetcher interface {
	Fetch(nsName, podName string) (*slim_corev1.Namespace, *slim_corev1.Pod, error)
}
