// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"

	"github.com/cilium/cilium/api/v1/models"
	health "github.com/cilium/cilium/cilium-health/launch"
	"github.com/cilium/cilium/pkg/bandwidth"
	"github.com/cilium/cilium/pkg/bgp/speaker"
	bgpv1 "github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/link"
	linuxdatapath "github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/datapath/loader"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/debug"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/egressgateway"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/eventqueue"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/hubble/observer"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/eppolicymap"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/maps/sockmap"
	"github.com/cilium/cilium/pkg/metrics"
	monitoragent "github.com/cilium/cilium/pkg/monitor/agent"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	nodemanager "github.com/cilium/cilium/pkg/node/manager"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	policyAPI "github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/probe"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/recorder"
	"github.com/cilium/cilium/pkg/redirectpolicy"
	"github.com/cilium/cilium/pkg/service"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
	"github.com/cilium/cilium/pkg/sockops"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/status"
	"github.com/cilium/cilium/pkg/trigger"
	wg "github.com/cilium/cilium/pkg/wireguard/agent"
	cnitypes "github.com/cilium/cilium/plugins/cilium-cni/types"
)

const (
	// AutoCIDR indicates that a CIDR should be allocated
	AutoCIDR = "auto"

	// ConfigModifyQueueSize is the size of the event queue for serializing
	// configuration updates to the daemon
	ConfigModifyQueueSize = 10

	syncEndpointsAndHostIPsController = "sync-endpoints-and-host-ips"
)

// Daemon is the cilium daemon that is in charge of perform all necessary plumbing,
// monitoring when a LXC starts.
type Daemon struct {
	ctx              context.Context
	cancel           context.CancelFunc
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

	monitorAgent *monitoragent.Agent
	ciliumHealth *health.CiliumHealth

	deviceManager *linuxdatapath.DeviceManager

	// dnsNameManager tracks which api.FQDNSelector are present in policy which
	// apply to locally running endpoints.
	dnsNameManager *fqdn.NameManager

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
	nodeDiscovery *nodediscovery.NodeDiscovery

	// ipam is the IP address manager of the agent
	ipam *ipam.IPAM

	netConf *cnitypes.NetConf

	endpointManager *endpointmanager.EndpointManager

	identityAllocator CachingIdentityAllocator

	ipcache *ipcache.IPCache

	k8sWatcher *watchers.K8sWatcher

	// healthEndpointRouting is the information required to set up the health
	// endpoint's routing in ENI or Azure IPAM mode
	healthEndpointRouting *linuxrouting.RoutingInfo

	linkCache      *link.LinkCache
	hubbleObserver *observer.LocalObserverServer

	// k8sCachesSynced is closed when all essential Kubernetes caches have
	// been fully synchronized
	k8sCachesSynced <-chan struct{}

	// endpointCreations is a map of all currently ongoing endpoint
	// creation events
	endpointCreations *endpointCreationManager

	redirectPolicyManager *redirectpolicy.Manager

	bgpSpeaker *speaker.MetalLBSpeaker

	egressGatewayManager *egressgateway.Manager

	apiLimiterSet *rate.APILimiterSet

	// event queue for serializing configuration updates to the daemon.
	configModifyQueue *eventqueue.EventQueue

	// controller for Cilium's BGP control plane.
	bgpControlPlaneController *bgpv1.Controller

	// CIDRs for which identities were restored during bootstrap
	restoredCIDRs []*net.IPNet

	// Controllers owned by the daemon
	controllers *controller.Manager
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

	// Remove any old sockops and re-enable with _new_ programs if flag is set
	sockops.SockmapDisable()
	sockops.SkmsgDisable()

	if !option.Config.DryMode {
		bandwidth.InitBandwidthManager()

		if err := d.createNodeConfigHeaderfile(); err != nil {
			return fmt.Errorf("failed while creating node config header file: %w", err)
		}

		if option.Config.SockopsEnable {
			eppolicymap.CreateEPPolicyMap()
			if err := sockops.SockmapEnable(); err != nil {
				return fmt.Errorf("failed to enable Sockmap: %w", err)
			} else if err := sockops.SkmsgEnable(); err != nil {
				return fmt.Errorf("failed to enable Sockmsg: %w", err)
			} else {
				sockmap.SockmapCreate()
			}
		}

		if err := d.Datapath().Loader().Reinitialize(d.ctx, d, d.mtuConfig.GetDeviceMTU(), d.Datapath(), d.l7Proxy); err != nil {
			return fmt.Errorf("failed while reinitializing datapath: %w", err)
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

// restoreCiliumHostIPs completes the `cilium_host` IP restoration process
// (part 2/2). This function is called after fully syncing with K8s to ensure
// that the most up-to-date information has been retrieved. At this point, the
// daemon is aware of all the necessary information to restore the appropriate
// IP.
func (d *Daemon) restoreCiliumHostIPs(ipv6 bool, fromK8s net.IP) {
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
	if err := removeOldRouterState(restoredIP); err != nil {
		log.WithError(err).Warnf(
			"Failed to remove old router IPs (restored IP: %s) from cilium_host. Manual intervention is required to remove all other old IPs.",
			restoredIP,
		)
	}
}

// removeOldRouterState will try to ensure that the only IP assigned to the
// `cilium_host` interface is the given restored IP. If the given IP is nil,
// then it attempts to clear all IPs from the interface.
func removeOldRouterState(restoredIP net.IP) error {
	l, err := netlink.LinkByName(defaults.HostDevice)
	if err != nil {
		return err
	}

	family := netlink.FAMILY_V6
	if restoredIP.To4() != nil {
		family = netlink.FAMILY_V4
	}
	addrs, err := netlink.AddrList(l, family)
	if err != nil {
		return err
	}
	if len(addrs) > 1 {
		log.Info("More than one router IP was found on the cilium_host device after restoration, cleaning up old router IPs.")
	}

	var errs []error
	for _, a := range addrs {
		if restoredIP != nil && restoredIP.Equal(a.IP) {
			continue
		}
		if err := netlink.AddrDel(l, &a); err != nil {
			errs = append(errs, fmt.Errorf("failed to remove IP %s: %w", a.IP, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("failed to remove all old router IPs: %v", errs)
	}

	return nil
}

// NewDaemon creates and returns a new Daemon with the parameters set in c.
func NewDaemon(ctx context.Context, cancel context.CancelFunc, epMgr *endpointmanager.EndpointManager, dp datapath.Datapath) (*Daemon, *endpointRestoreState, error) {

	// Pass the cancel to our signal handler directly so that it's canceled
	// before we run the cleanup functions (see `cleanup.go` for implementation).
	cleaner.SetCancelFunc(cancel)

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
			log.WithError(err).Error("Unable to read CNI configuration")
			return nil, nil, fmt.Errorf("unable to read CNI configuration: %w", err)
		}

		if netConf.MTU != 0 {
			configuredMTU = netConf.MTU
			log.WithField("mtu", configuredMTU).Info("Overwriting MTU based on CNI configuration")
		}
	}

	apiLimiterSet, err := rate.NewAPILimiterSet(option.Config.APIRateLimit, apiRateLimitDefaults, &apiRateLimitingMetrics{})
	if err != nil {
		log.WithError(err).Error("unable to configure API rate limiting")
		return nil, nil, fmt.Errorf("unable to configure API rate limiting: %w", err)
	}

	// Check the kernel if we can make use of managed neighbor entries which
	// simplifies and fully 'offloads' L2 resolution handling to the kernel.
	probeManagedNeighborSupport()

	// Do the partial kube-proxy replacement initialization before creating BPF
	// maps. Otherwise, some maps might not be created (e.g. session affinity).
	// finishKubeProxyReplacementInit(), which is called later after the device
	// detection, might disable BPF NodePort and friends. But this is fine, as
	// the feature does not influence the decision which BPF maps should be
	// created.
	isKubeProxyReplacementStrict, err := initKubeProxyReplacementOptions()
	if err != nil {
		log.WithError(err).Error("unable to initialize Kube proxy replacement options")
		return nil, nil, fmt.Errorf("unable to initialize Kube proxy replacement options: %w", err)
	}

	ctmap.InitMapInfo(option.Config.CTMapEntriesGlobalTCP, option.Config.CTMapEntriesGlobalAny,
		option.Config.EnableIPv4, option.Config.EnableIPv6, option.Config.EnableNodePort)
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

	if option.Config.DryMode == false {
		if err := rlimit.RemoveMemlock(); err != nil {
			log.WithError(err).Error("unable to set memory resource limits")
			return nil, nil, fmt.Errorf("unable to set memory resource limits: %w", err)
		}
	}

	authKeySize, encryptKeyID, err := setupIPSec()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to setup encryption: %s", err)
	}

	var mtuConfig mtu.Configuration
	externalIP := node.GetIPv4()
	if externalIP == nil {
		externalIP = node.GetIPv6()
	}
	// ExternalIP could be nil but we are covering that case inside NewConfiguration
	mtuConfig = mtu.NewConfiguration(
		authKeySize,
		option.Config.EnableIPSec,
		option.Config.TunnelingEnabled(),
		option.Config.EnableWireguard,
		configuredMTU,
		externalIP,
	)

	nodeMngr, err := nodemanager.NewManager("all", dp.Node(), option.Config, nil, nil)
	if err != nil {
		return nil, nil, err
	}

	identity.IterateReservedIdentities(func(_ identity.NumericIdentity, _ *identity.Identity) {
		metrics.Identity.WithLabelValues(identity.ReservedIdentityType).Inc()
	})
	if option.Config.EnableWellKnownIdentities {
		// Must be done before calling policy.NewPolicyRepository() below.
		num := identity.InitWellKnownIdentities(option.Config)
		metrics.Identity.WithLabelValues(identity.WellKnownIdentityType).Add(float64(num))
	}

	nd := nodediscovery.NewNodeDiscovery(nodeMngr, mtuConfig, netConf)

	devMngr, err := linuxdatapath.NewDeviceManager()
	if err != nil {
		return nil, nil, err
	}

	d := Daemon{
		ctx:               ctx,
		cancel:            cancel,
		prefixLengths:     createPrefixLengthCounter(),
		buildEndpointSem:  semaphore.NewWeighted(int64(numWorkerThreads())),
		compilationMutex:  new(lock.RWMutex),
		netConf:           netConf,
		mtuConfig:         mtuConfig,
		datapath:          dp,
		deviceManager:     devMngr,
		nodeDiscovery:     nd,
		endpointCreations: newEndpointCreationManager(),
		apiLimiterSet:     apiLimiterSet,
		controllers:       controller.NewManager(),
	}

	if option.Config.RunMonitorAgent {
		d.monitorAgent = monitoragent.NewAgent(ctx)
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
	var oldIngressIPs []*net.IPNet
	if option.Config.RestoreState && !option.Config.DryMode {
		if err := ipcachemap.IPCache.DumpWithCallback(func(key bpf.MapKey, value bpf.MapValue) {
			k := key.(*ipcachemap.Key)
			v := value.(*ipcachemap.RemoteEndpointInfo)
			nid := identity.NumericIdentity(v.SecurityIdentity)
			if nid.HasLocalScope() {
				d.restoredCIDRs = append(d.restoredCIDRs, k.IPNet())
				oldNIDs = append(oldNIDs, nid)
			} else if nid == identity.ReservedIdentityIngress && v.TunnelEndpoint.IsZero() {
				oldIngressIPs = append(oldIngressIPs, k.IPNet())
				ip := k.IPNet().IP
				if ip.To4() != nil {
					node.SetIngressIPv4(ip)
				} else {
					node.SetIngressIPv6(ip)
				}
			}
		}); err != nil && !os.IsNotExist(err) {
			log.WithError(err).Debug("Error dumping ipcache")
		}
		// DumpWithCallback() leaves the ipcache map open, must close before opened for
		// parallel mode in Daemon.initMaps()
		ipcachemap.IPCache.Close()
	}

	// Propagate identity allocator down to packages which themselves do not
	// have types to which we can add an allocator member.
	//
	// **NOTE** The global identity allocator is not yet initialized here; that
	// happens below vie InitIdentityAllocator(). Only the local identity allocator
	// is initialized here.
	//
	// TODO: convert these package level variables to types for easier unit
	// testing in the future.
	d.identityAllocator = NewCachingIdentityAllocator(&d)
	if err := d.initPolicy(epMgr); err != nil {
		return nil, nil, fmt.Errorf("error while initializing policy subsystem: %w", err)
	}
	d.ipcache = ipcache.NewIPCache(&ipcache.Configuration{
		IdentityAllocator: d.identityAllocator,
		PolicyHandler:     d.policy.GetSelectorCache(),
		DatapathHandler:   epMgr,
	})
	// Preallocate IDs for old CIDRs. This must be done before any Identity allocations are
	// possible so that the old IDs are still available. That is why we do this ASAP after the
	// new (userspace) ipcache is created above.
	//
	// CIDRs were dumped from the old ipcache, they are re-allocated here, hopefully with the
	// same numeric IDs as before, but the restored identities are to be upsterted to the new
	// (datapath) ipcache after it has been initialized below. This is accomplished by passing
	// 'restoredCIDRidentities' to AllocateCIDRs() and then calling
	// UpsertGeneratedIdentities(restoredCIDRidentities) after initMaps() below.
	restoredCIDRidentities := make(map[string]*identity.Identity)
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
			id, exists := restoredCIDRidentities[prefix.String()]
			if !exists || id.ID != oldNIDs[i] {
				log.WithField(logfields.Identity, oldNIDs[i]).Warn("Could not restore all CIDR identities")
				break
			}
		}
	}
	nodeMngr = nodeMngr.WithIPCache(d.ipcache)
	nodeMngr = nodeMngr.WithSelectorCacheUpdater(d.policy.GetSelectorCache()) // must be after initPolicy
	nodeMngr = nodeMngr.WithPolicyTriggerer(epMgr)                            // must be after initPolicy

	proxy.Allocator = d.identityAllocator

	d.endpointManager = epMgr
	d.endpointManager.InitMetrics()

	// Start the proxy before we start K8s watcher or restore endpoints so that we can inject
	// the daemon's proxy into the k8s watcher and each endpoint.
	// Note: d.endpointManager needs to be set before this
	bootstrapStats.proxyStart.Start()
	// FIXME: Make the port range configurable.
	if option.Config.EnableL7Proxy {
		d.l7Proxy = proxy.StartProxySupport(10000, 20000, option.Config.RunDir,
			&d, option.Config.AgentLabels, d.datapath, d.endpointManager, d.ipcache)
	} else {
		log.Info("L7 proxies are disabled")
		if option.Config.EnableEnvoyConfig {
			log.Warningf("%s is not functional when L7 proxies are disabled",
				option.EnableEnvoyConfig)
		}
	}
	bootstrapStats.proxyStart.End(true)

	// Start service support after proxy support so that we can inject 'd.l7Proxy`.
	d.svc = service.NewService(&d, d.l7Proxy)

	d.redirectPolicyManager = redirectpolicy.NewRedirectPolicyManager(d.svc)
	if option.Config.BGPAnnounceLBIP || option.Config.BGPAnnouncePodCIDR {
		d.bgpSpeaker, err = speaker.New(ctx, speaker.Opts{
			LoadBalancerIP: option.Config.BGPAnnounceLBIP,
			PodCIDR:        option.Config.BGPAnnouncePodCIDR,
		})
		if err != nil {
			log.WithError(err).Error("Error creating new BGP speaker")
			return nil, nil, err
		}
	}

	if option.Config.EnableIPv4EgressGateway {
		d.egressGatewayManager = egressgateway.NewEgressGatewayManager(&d, d.identityAllocator)
	}

	d.k8sWatcher = watchers.NewK8sWatcher(
		d.endpointManager,
		d.nodeDiscovery,
		&d,
		d.policy,
		d.svc,
		d.datapath,
		d.redirectPolicyManager,
		d.bgpSpeaker,
		d.egressGatewayManager,
		d.l7Proxy,
		option.Config,
		d.ipcache,
	)
	nd.RegisterK8sNodeGetter(d.k8sWatcher)
	d.ipcache.RegisterK8sSyncedChecker(&d)

	d.k8sWatcher.RegisterNodeSubscriber(d.endpointManager)
	if option.Config.BGPAnnounceLBIP || option.Config.BGPAnnouncePodCIDR {
		switch option.Config.IPAMMode() {
		case ipamOption.IPAMKubernetes:
			d.k8sWatcher.RegisterNodeSubscriber(d.bgpSpeaker)
		case ipamOption.IPAMClusterPool:
			d.k8sWatcher.RegisterCiliumNodeSubscriber(d.bgpSpeaker)
		}
	}
	if option.Config.EnableServiceTopology {
		d.k8sWatcher.RegisterNodeSubscriber(&d.k8sWatcher.K8sSvcCache)
	}

	d.k8sWatcher.NodeChain.Register(watchers.NewCiliumNodeUpdater(d.k8sWatcher, d.nodeDiscovery))

	d.redirectPolicyManager.RegisterSvcCache(&d.k8sWatcher.K8sSvcCache)
	d.redirectPolicyManager.RegisterGetStores(d.k8sWatcher)
	if option.Config.BGPAnnounceLBIP {
		d.bgpSpeaker.RegisterSvcCache(&d.k8sWatcher.K8sSvcCache)
	}

	bootstrapStats.daemonInit.End(true)

	// Stop all endpoints (its goroutines) on exit.
	cleaner.cleanupFuncs.Add(func() {
		log.Info("Waiting for all endpoints' go routines to be stopped.")
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
		d.ipcache.UpsertGeneratedIdentities(restoredCIDRidentities)
	}
	// Upsert restored local Ingress IPs
	restoredIngressIPs := []string{}
	for _, ingressIP := range oldIngressIPs {
		_, err := d.ipcache.Upsert(ingressIP.String(), nil, 0, nil, ipcache.Identity{
			ID:     identity.ReservedIdentityIngress,
			Source: source.Restored,
		})
		if err == nil {
			restoredIngressIPs = append(restoredIngressIPs, ingressIP.String())
		} else {
			log.WithError(err).Warning("could not restore Ingress IP, a new one will be allocated")
		}
	}
	if len(restoredIngressIPs) > 0 {
		log.WithField(logfields.Ingress, restoredIngressIPs).Info("Restored ingress IPs")
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

	debug.RegisterStatusObject("k8s-service-cache", &d.k8sWatcher.K8sSvcCache)
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
	policyAPI.InitEntities(option.Config.ClusterName, treatRemoteNodeAsHost)

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
	bootstrapStats.fqdn.End(true)

	if k8s.IsEnabled() {
		bootstrapStats.k8sInit.Start()
		// Errors are handled inside WaitForCRDsToRegister. It will fatal on a
		// context deadline or if the context has been cancelled, the context's
		// error will be returned. Otherwise, it succeeded.
		if err := d.k8sWatcher.WaitForCRDsToRegister(d.ctx); err != nil {
			return nil, restoredEndpoints, err
		}

		// Launch the K8s node watcher so we can start receiving node events.
		// Launching the k8s node watcher at this stage will prevent all agents
		// from performing Gets directly into kube-apiserver to get the most up
		// to date version of the k8s node. This allows for better scalability
		// in large clusters.
		d.k8sWatcher.NodesInit(k8s.Client())

		if option.Config.IPAM == ipamOption.IPAMClusterPool || option.Config.IPAM == ipamOption.IPAMClusterPoolV2 {
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

	if wgAgent := dp.WireguardAgent(); option.Config.EnableWireguard {
		if err := wgAgent.(*wg.Agent).Init(d.ipcache, mtuConfig); err != nil {
			log.WithError(err).Error("failed to initialize wireguard agent")
			return nil, nil, fmt.Errorf("failed to initialize wireguard agent: %w", err)
		}
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
	if _, err := d.deviceManager.Detect(); err != nil {
		if d.deviceManager.AreDevicesRequired() {
			// Fail hard if devices are required to function.
			return nil, nil, fmt.Errorf("failed to detect devices: %w", err)
		}
		log.WithError(err).Warn("failed to detect devices, disabling BPF NodePort")
		disableNodePort()
	}
	if err := finishKubeProxyReplacementInit(isKubeProxyReplacementStrict); err != nil {
		log.WithError(err).Error("failed to finalise LB initialization")
		return nil, nil, fmt.Errorf("failed to finalise LB initialization: %w", err)
	}

	// BPF masquerade depends on BPF NodePort and require host-reachable svc to
	// be fully enabled in the tunneling mode, so the following checks should
	// happen after invoking initKubeProxyReplacementOptions().
	if option.Config.EnableIPv4Masquerade && option.Config.EnableBPFMasquerade &&
		(!option.Config.EnableNodePort || option.Config.EgressMasqueradeInterfaces != "" || !option.Config.EnableRemoteNodeIdentity ||
			(option.Config.TunnelingEnabled() && !hasFullHostReachableServices())) {

		var msg string
		switch {
		case !option.Config.EnableNodePort:
			msg = fmt.Sprintf("BPF masquerade requires NodePort (--%s=\"true\").",
				option.EnableNodePort)
		case !option.Config.EnableRemoteNodeIdentity:
			msg = fmt.Sprintf("BPF masquerade requires remote node identities (--%s=\"true\").",
				option.EnableRemoteNodeIdentity)
		case option.Config.EgressMasqueradeInterfaces != "":
			msg = fmt.Sprintf("BPF masquerade does not allow to specify devices via --%s (use --%s instead).",
				option.EgressMasqueradeInterfaces, option.Devices)
		}
		// ipt.InstallRules() (called by Reinitialize()) happens later than
		// this  statement, so it's OK to fallback to iptables-based MASQ.
		option.Config.EnableBPFMasquerade = false
		log.Warn(msg + " Falling back to iptables-based masquerading.")
		// Too bad, if we need to revert to iptables-based MASQ, we also cannot
		// use BPF host routing since we need the upper stack.
		if !option.Config.EnableHostLegacyRouting {
			option.Config.EnableHostLegacyRouting = true
			log.Infof("BPF masquerade could not be enabled. Falling back to legacy host routing (--%s=\"true\").",
				option.EnableHostLegacyRouting)
		}
	}
	if option.Config.EnableIPv4EgressGateway {
		if !probes.NewProbeManager().GetMisc().HaveLargeInsnLimit {
			log.WithError(err).Error("egress gateway needs kernel 5.2 or newer")
			return nil, nil, fmt.Errorf("egress gateway needs kernel 5.2 or newer")
		}

		// datapath code depends on remote node identities to distinguish between cluser-local and
		// cluster-egress traffic
		if !option.Config.EnableRemoteNodeIdentity {
			log.WithError(err).Errorf("egress gateway requires remote node identities (--%s=\"true\").",
				option.EnableRemoteNodeIdentity)
			return nil, nil, fmt.Errorf("egress gateway requires remote node identities (--%s=\"true\").",
				option.EnableRemoteNodeIdentity)
		}

		if option.Config.EnableL7Proxy {
			log.WithField(logfields.URL, "https://github.com/cilium/cilium/issues/19642").
				Warningf("both egress gateway and L7 proxy (--%s) are enabled. This is currently not fully supported: "+
					"if the same endpoint is selected both by an egress gateway and a L7 policy, endpoint traffic will not go through egress gateway.", option.EnableL7Proxy)
		}
	}
	if option.Config.EnableIPv4Masquerade && option.Config.EnableBPFMasquerade {
		// TODO(brb) nodeport + ipvlan constraints will be lifted once the SNAT BPF code has been refactored
		if option.Config.DatapathMode == datapathOption.DatapathModeIpvlan {
			log.WithError(err).Errorf("BPF masquerade works only in veth mode (--%s=\"%s\"", option.DatapathMode, datapathOption.DatapathModeVeth)
			return nil, nil, fmt.Errorf("BPF masquerade works only in veth mode (--%s=\"%s\"", option.DatapathMode, datapathOption.DatapathModeVeth)
		}
		if err := node.InitBPFMasqueradeAddrs(option.Config.GetDevices()); err != nil {
			log.WithError(err).Error("failed to determine BPF masquerade IPv4 addrs")
			return nil, nil, fmt.Errorf("failed to determine BPF masquerade IPv4 addrs: %w", err)
		}
	} else if option.Config.EnableIPMasqAgent {
		log.WithError(err).Errorf("BPF ip-masq-agent requires --%s=\"true\" and --%s=\"true\"", option.EnableIPv4Masquerade, option.EnableBPFMasquerade)
		return nil, nil, fmt.Errorf("BPF ip-masq-agent requires --%s=\"true\" and --%s=\"true\"", option.EnableIPv4Masquerade, option.EnableBPFMasquerade)
	} else if option.Config.EnableIPv4EgressGateway {
		log.WithError(err).Errorf("egress gateway requires --%s=\"true\" and --%s=\"true\"", option.EnableIPv4Masquerade, option.EnableBPFMasquerade)
		return nil, nil, fmt.Errorf("egress gateway requires --%s=\"true\" and --%s=\"true\"", option.EnableIPv4Masquerade, option.EnableBPFMasquerade)
	} else if !option.Config.EnableIPv4Masquerade && option.Config.EnableBPFMasquerade {
		// There is not yet support for option.Config.EnableIPv6Masquerade
		log.Infof("Auto-disabling %q feature since IPv4 masquerading was generally disabled",
			option.EnableBPFMasquerade)
		option.Config.EnableBPFMasquerade = false
	}
	if option.Config.EnableIPMasqAgent {
		if !option.Config.EnableIPv4 {
			log.WithError(err).Errorf("BPF ip-masq-agent requires IPv4 support (--%s=\"true\")", option.EnableIPv4Name)
			return nil, nil, fmt.Errorf("BPF ip-masq-agent requires IPv4 support (--%s=\"true\")", option.EnableIPv4Name)
		}
		if !probe.HaveFullLPM() {
			log.WithError(err).Error("BPF ip-masq-agent needs kernel 4.16 or newer")
			return nil, nil, fmt.Errorf("BPF ip-masq-agent needs kernel 4.16 or newer")
		}
	}
	if option.Config.EnableHostFirewall && len(option.Config.GetDevices()) == 0 {
		msg := "host firewall's external facing device could not be determined. Use --%s to specify."
		log.WithError(err).Errorf(msg, option.Devices)
		return nil, nil, fmt.Errorf(msg, option.Devices)
	}

	// Some of the k8s watchers rely on option flags set above (specifically
	// EnableBPFMasquerade), so we should only start them once the flag values
	// are set.
	if k8s.IsEnabled() {
		bootstrapStats.k8sInit.Start()

		// Initialize d.k8sCachesSynced before any k8s watchers are alive, as they may
		// access it to check the status of k8s initialization
		cachesSynced := make(chan struct{})
		d.k8sCachesSynced = cachesSynced

		// Launch the K8s watchers in parallel as we continue to process other
		// daemon options.
		d.k8sWatcher.InitK8sSubsystem(d.ctx, cachesSynced)
		bootstrapStats.k8sInit.End(true)
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
		if k8s.IsEnabled() {
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
		d.nodeDiscovery.JoinCluster(nodeTypes.GetName())

		// Start services watcher
		serviceStore.JoinClusterServices(&d.k8sWatcher.K8sSvcCache, option.Config)
	}

	// Start IPAM
	d.startIPAM()
	// After the IPAM is started, in particular IPAM modes (CRD, ENI, Alibaba)
	// which use the VPC CIDR as the pod CIDR, we must attempt restoring the
	// router IPs from the K8s resources if we weren't able to restore them
	// from the fs. We must do this after IPAM because we must wait until the
	// K8s resources have been synced. Part 2/2 of restoration.
	if option.Config.EnableIPv4 {
		d.restoreCiliumHostIPs(false, router4FromK8s)
	}
	if option.Config.EnableIPv6 {
		d.restoreCiliumHostIPs(true, router6FromK8s)
	}

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

	// Must occur after d.allocateIPs(), see GH-14245 and its fix.
	d.nodeDiscovery.StartDiscovery()

	// Annotation of the k8s node must happen after discovery of the
	// PodCIDR range and allocation of the health IPs.
	if k8s.IsEnabled() && option.Config.AnnotateK8sNode {
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

		err := k8s.Client().AnnotateNode(nodeTypes.GetName(),
			encryptKeyID,
			node.GetIPv4AllocRange(), node.GetIPv6AllocRange(),
			node.GetEndpointHealthIPv4(), node.GetEndpointHealthIPv6(),
			node.GetIngressIPv4(), node.GetIngressIPv6(),
			node.GetInternalIPv4Router(), node.GetIPv6Router())
		if err != nil {
			log.WithError(err).Warning("Cannot annotate k8s node with CIDR range")
		}
		bootstrapStats.k8sInit.End(true)
	} else if !option.Config.AnnotateK8sNode {
		log.Debug("Annotate k8s node is disabled.")
	}

	// Trigger refresh and update custom resource in the apiserver with all restored endpoints.
	// Trigger after nodeDiscovery.StartDiscovery to avoid custom resource update conflict.
	if option.Config.IPAM == ipamOption.IPAMCRD || option.Config.IPAM == ipamOption.IPAMENI || option.Config.IPAM == ipamOption.IPAMAzure ||
		option.Config.IPAM == ipamOption.IPAMAlibabaCloud || option.Config.IPAM == ipamOption.IPAMClusterPoolV2 {
		if option.Config.EnableIPv6 {
			d.ipam.IPv6Allocator.RestoreFinished()
		}
		if option.Config.EnableIPv4 {
			d.ipam.IPv4Allocator.RestoreFinished()
		}
	}

	if option.Config.DatapathMode != datapathOption.DatapathModeLBOnly {
		// This needs to be done after the node addressing has been configured
		// as the node address is required as suffix.
		// well known identities have already been initialized above.
		// Ignore the channel returned by this function, as we want the global
		// identity allocator to run asynchronously.
		realIdentityAllocator := d.identityAllocator
		realIdentityAllocator.InitIdentityAllocator(k8s.CiliumClient(), nil)

		d.bootstrapClusterMesh(nodeMngr)
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

	// We can only attach the monitor agent once cilium_event has been set up.
	if option.Config.RunMonitorAgent {
		err = d.monitorAgent.AttachToEventsMap(defaults.MonitorBufferPages)
		if err != nil {
			log.WithError(err).Error("encountered error configuring run monitor agent")
			return nil, nil, fmt.Errorf("encountered error configuring run monitor agent: %w", err)
		}

		if option.Config.EnableMonitor {
			err = monitoragent.ServeMonitorAPI(d.monitorAgent)
			if err != nil {
				log.WithError(err).Error("encountered error configuring run monitor agent")
				return nil, nil, fmt.Errorf("encountered error configuring run monitor agent: %w", err)
			}
		}
	}

	// Start the controller for periodic sync. The purpose of the
	// controller is to ensure that endpoints and host IPs entries are
	// reinserted to the bpf maps if they are ever removed from them.
	syncErrs := make(chan error, 1)
	d.controllers.UpdateController(
		syncEndpointsAndHostIPsController,
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				err := d.syncEndpointsAndHostIPs()
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
	d.ipcache.InitIPIdentityWatcher()
	identitymanager.Subscribe(d.policy)

	// Start listening to changed devices if requested.
	if option.Config.EnableRuntimeDeviceDetection {
		if d.deviceManager.AreDevicesRequired() {
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
		if err := ipsec.StartKeyfileWatcher(ctx, option.Config.IPSecKeyFile, nd); err != nil {
			log.WithError(err).Error("Unable to start IPSec keyfile watcher")
		}
	}

	return &d, restoredEndpoints, nil
}

// WithDefaultEndpointManager creates the default endpoint manager with a
// functional endpoint synchronizer.
func WithDefaultEndpointManager(ctx context.Context, checker endpointmanager.EndpointCheckerFunc) *endpointmanager.EndpointManager {
	mgr := WithCustomEndpointManager(&watchers.EndpointSynchronizer{})
	if option.Config.EndpointGCInterval > 0 {
		mgr = mgr.WithPeriodicEndpointGC(ctx, checker, option.Config.EndpointGCInterval)
	}
	return mgr
}

// WithCustomEndpointManager creates the custom endpoint manager with the
// provided endpoint synchronizer. This is useful for tests which want to mock
// out the real endpoint synchronizer.
func WithCustomEndpointManager(s endpointmanager.EndpointResourceSynchronizer) *endpointmanager.EndpointManager {
	return endpointmanager.NewEndpointManager(s)
}

func (d *Daemon) bootstrapClusterMesh(nodeMngr *nodemanager.Manager) {
	bootstrapStats.clusterMeshInit.Start()
	if path := option.Config.ClusterMeshConfig; path != "" {
		if option.Config.ClusterID == 0 {
			log.Info("Cluster-ID is not specified, skipping ClusterMesh initialization")
		} else {
			log.WithField("path", path).Info("Initializing ClusterMesh routing")
			clustermesh, err := clustermesh.NewClusterMesh(clustermesh.Configuration{
				Name:                  option.Config.ClusterName,
				NodeName:              nodeTypes.GetName(),
				ConfigDirectory:       path,
				NodeKeyCreator:        nodeStore.KeyCreator,
				ServiceMerger:         &d.k8sWatcher.K8sSvcCache,
				NodeManager:           nodeMngr,
				RemoteIdentityWatcher: d.identityAllocator,
				IPCache:               d.ipcache,
			})
			if err != nil {
				log.WithError(err).Fatal("Unable to initialize ClusterMesh")
			}

			d.clustermesh = clustermesh
		}
	}
	bootstrapStats.clusterMeshInit.End(true)
}

// ReloadOnDeviceChange regenerates device related information and reloads the datapath.
// The devices is the new set of devices that replaces the old set.
func (d *Daemon) ReloadOnDeviceChange(devices []string) {
	option.Config.SetDevices(devices)

	if option.Config.EnableIPv4Masquerade && option.Config.EnableBPFMasquerade {
		if err := node.InitBPFMasqueradeAddrs(devices); err != nil {
			log.Warnf("InitBPFMasqueradeAddrs failed: %s", err)
		}
	}

	if option.Config.EnableNodePort {
		if err := node.InitNodePortAddrs(devices, option.Config.LBDevInheritIPAddr); err != nil {
			log.WithError(err).Warn("Failed to initialize NodePort addresses")
		} else {
			// Synchronize services and endpoints to reflect new addresses onto lbmap.
			d.svc.SyncServicesOnDeviceChange(d.Datapath().LocalNodeAddressing())
			d.controllers.TriggerController(syncEndpointsAndHostIPsController)
		}
	}

	// Recreate node_config.h to reflect the mac addresses of the new devices.
	d.compilationMutex.Lock()
	err := d.createNodeConfigHeaderfile()
	d.compilationMutex.Unlock()
	if err != nil {
		log.WithError(err).Warn("Failed to re-create node config header")
		return
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
	if d.policyUpdater != nil {
		d.policyUpdater.Shutdown()
	}
	if d.datapathRegenTrigger != nil {
		d.datapathRegenTrigger.Shutdown()
	}
	d.nodeDiscovery.Close()
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
func (d *Daemon) SendNotification(notification monitorAPI.AgentNotifyMessage) error {
	if option.Config.DryMode {
		return nil
	}
	return d.monitorAgent.SendEvent(monitorAPI.MessageTypeAgent, notification)
}

// GetNodeSuffix returns the suffix to be appended to kvstore keys of this
// agent
func (d *Daemon) GetNodeSuffix() string {
	var ip net.IP

	switch {
	case option.Config.EnableIPv4:
		ip = node.GetIPv4()
	case option.Config.EnableIPv6:
		ip = node.GetIPv6()
	}

	if ip == nil {
		log.Fatal("Node IP not available yet")
	}

	return ip.String()
}

// K8sCacheIsSynced returns true if the agent has fully synced its k8s cache
// with the API server
func (d *Daemon) K8sCacheIsSynced() bool {
	if !k8s.IsEnabled() {
		return true
	}
	select {
	case <-d.k8sCachesSynced:
		return true
	default:
		return false
	}
}
