// Copyright 2016-2020 Authors of Cilium
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

package cmd

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
	"github.com/cilium/cilium/pkg/bandwidth"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/datapath"
	linuxdatapath "github.com/cilium/cilium/pkg/datapath/linux"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/datapath/loader"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/debug"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/hubble/observer"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/watchers"
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
	policyApi "github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/probe"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/service"
	"github.com/cilium/cilium/pkg/sockops"
	"github.com/cilium/cilium/pkg/status"
	"github.com/cilium/cilium/pkg/trigger"
	cnitypes "github.com/cilium/cilium/plugins/cilium-cni/types"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
)

const (
	// AutoCIDR indicates that a CIDR should be allocated
	AutoCIDR = "auto"
)

// Daemon is the cilium daemon that is in charge of perform all necessary plumbing,
// monitoring when a LXC starts.
type Daemon struct {
	ctx              context.Context
	cancel           context.CancelFunc
	buildEndpointSem *semaphore.Weighted
	l7Proxy          *proxy.Proxy
	svc              *service.Service
	policy           *policy.Repository
	preFilter        datapath.PreFilter

	statusCollectMutex lock.RWMutex
	statusResponse     models.StatusResponse
	statusCollector    *status.Collector

	monitorAgent *monitoragent.Agent
	ciliumHealth *health.CiliumHealth

	// dnsNameManager tracks which api.FQDNSelector are present in policy which
	// apply to locally running endpoints.
	dnsNameManager *fqdn.NameManager

	// dnsPoller polls DNS names and sends them to dnsNameManager
	dnsPoller *fqdn.DNSPoller

	// Used to synchronize generation of daemon's BPF programs and endpoint BPF
	// programs.
	compilationMutex *lock.RWMutex

	// prefixLengths tracks a mapping from CIDR prefix length to the count
	// of rules that refer to that prefix length.
	prefixLengths *counter.PrefixLengthCounter

	clustermesh *clustermesh.ClusterMesh

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

	endpointManager *endpointmanager.EndpointManager

	identityAllocator *cache.CachingIdentityAllocator

	k8sWatcher *watchers.K8sWatcher

	// healthEndpointRouting is the information required to set up the health
	// endpoint's routing in ENI or Azure IPAM mode
	healthEndpointRouting *linuxrouting.RoutingInfo

	hubbleObserver *observer.LocalObserverServer

	// k8sCachesSynced is closed when all essential Kubernetes caches have
	// been fully synchronized
	k8sCachesSynced <-chan struct{}

	// endpointCreations is a map of all currently ongoing endpoint
	// creation events
	endpointCreations *endpointCreationManager
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
			return err
		}

		if option.Config.SockopsEnable {
			eppolicymap.CreateEPPolicyMap()
			if err := sockops.SockmapEnable(); err != nil {
				log.WithError(err).Error("Failed to enable Sockmap")
			} else if err := sockops.SkmsgEnable(); err != nil {
				log.WithError(err).Error("Failed to enable Sockmsg")
			} else {
				sockmap.SockmapCreate()
			}
		}

		if err := d.Datapath().Loader().Reinitialize(d.ctx, d, d.mtuConfig.GetDeviceMTU(), d.Datapath(), d.l7Proxy); err != nil {
			return err
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

// NewDaemon creates and returns a new Daemon with the parameters set in c.
func NewDaemon(ctx context.Context, epMgr *endpointmanager.EndpointManager, dp datapath.Datapath) (*Daemon, *endpointRestoreState, error) {

	dCtx, cancel := context.WithCancel(ctx)
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
	policymap.InitMapInfo(option.Config.PolicyMapEntries)
	lbmap.InitMapInfo(option.Config.SockRevNatEntries, option.Config.LBMapEntries)

	if option.Config.DryMode == false {
		if err := bpf.ConfigureResourceLimits(); err != nil {
			log.WithError(err).Fatal("Unable to set memory resource limits")
		}
	}

	authKeySize, encryptKeyID, err := setupIPSec()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to setup encryption: %s", err)
	}

	var mtuConfig mtu.Configuration
	externalIP := node.GetExternalIPv4()
	if externalIP == nil {
		externalIP = node.GetIPv6()
	}
	// ExternalIP could be nil but we are covering that case inside NewConfiguration
	mtuConfig = mtu.NewConfiguration(authKeySize, option.Config.EnableIPSec, option.Config.Tunnel != option.TunnelDisabled, configuredMTU, externalIP)

	nodeMngr, err := nodemanager.NewManager("all", dp.Node(), ipcache.IPIdentityCache, option.Config)
	if err != nil {
		return nil, nil, err
	}

	identity.IterateReservedIdentities(func(_ string, _ identity.NumericIdentity) {
		metrics.Identity.Inc()
		metrics.IdentityCount.Inc()
	})
	if option.Config.EnableWellKnownIdentities {
		// Must be done before calling policy.NewPolicyRepository() below.
		num := identity.InitWellKnownIdentities(option.Config)
		metrics.Identity.Add(float64(num))
		metrics.IdentityCount.Add(float64(num))
	}

	nd := nodediscovery.NewNodeDiscovery(nodeMngr, mtuConfig, netConf)

	d := Daemon{
		ctx:               dCtx,
		cancel:            cancel,
		prefixLengths:     createPrefixLengthCounter(),
		buildEndpointSem:  semaphore.NewWeighted(int64(numWorkerThreads())),
		compilationMutex:  new(lock.RWMutex),
		netConf:           netConf,
		mtuConfig:         mtuConfig,
		datapath:          dp,
		nodeDiscovery:     nd,
		endpointCreations: newEndpointCreationManager(),
	}

	d.svc = service.NewService(&d)

	d.identityAllocator = cache.NewCachingIdentityAllocator(&d)
	d.policy = policy.NewPolicyRepository(d.identityAllocator.GetIdentityCache(),
		certificatemanager.NewManager(option.Config.CertDirectory, k8s.Client()))
	d.policy.SetEnvoyRulesFunc(envoy.GetEnvoyHTTPRules)

	// Propagate identity allocator down to packages which themselves do not
	// have types to which we can add an allocator member.
	//
	// TODO: convert these package level variables to types for easier unit
	// testing in the future.
	ipcache.IdentityAllocator = d.identityAllocator
	proxy.Allocator = d.identityAllocator

	d.endpointManager = epMgr
	d.endpointManager.InitMetrics()

	d.k8sWatcher = watchers.NewK8sWatcher(
		d.endpointManager,
		d.nodeDiscovery.Manager,
		&d,
		d.policy,
		d.svc,
		d.datapath,
	)

	bootstrapStats.daemonInit.End(true)

	// Cleanup on exit if running in tandem with Flannel.
	if option.Config.FlannelUninstallOnExit {
		cleaner.cleanupFuncs.Add(func() {
			for _, ep := range d.endpointManager.GetEndpoints() {
				ep.DeleteBPFProgramLocked()
			}
		})
	}

	// Do the partial kube-proxy replacement initialization before creating BPF
	// maps. Otherwise, some maps might not be created (e.g. session affinity).
	// finishKubeProxyReplacementInit(), which is called later after the device
	// detection, might disable BPF NodePort and friends. But this is fine, as
	// the feature does not influence the decision which BPF maps should be
	// created.
	isKubeProxyReplacementStrict := initKubeProxyReplacementOptions()

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
		d.svc.RestoreServices()
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

	debug.RegisterStatusObject("k8s-service-cache", &d.k8sWatcher.K8sSvcCache)
	debug.RegisterStatusObject("ipam", d.ipam)
	debug.RegisterStatusObject("ongoing-endpoint-creations", d.endpointCreations)

	d.k8sWatcher.RunK8sServiceHandler()
	treatRemoteNodeAsHost := option.Config.AlwaysAllowLocalhost() && !option.Config.EnableRemoteNodeIdentity
	policyApi.InitEntities(option.Config.ClusterName, treatRemoteNodeAsHost)

	if k8s.IsEnabled() {
		bootstrapStats.k8sInit.Start()
		if err := k8s.RegisterCRDs(); err != nil {
			log.WithError(err).Fatal("Unable to register CRDs")
		}

		if option.Config.IPAM == ipamOption.IPAMOperator {
			// Create the CiliumNode custom resource. This call will block until
			// the custom resource has been created
			d.nodeDiscovery.UpdateCiliumNodeResource()
		}

		if err := k8s.GetNodeSpec(); err != nil {
			log.WithError(err).Fatal("Unable to connect to get node spec from apiserver")
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

	// Perform an early probe on the underlying kernel on whether BandwidthManager
	// can be supported or not. This needs to be done before detectNativeDevices()
	// as BandwidthManager needs these to be available for setup.
	bandwidth.ProbeBandwidthManager()

	// The kube-proxy replacement and host-fw devices detection should happen after
	// establishing a connection to kube-apiserver, but before starting a k8s watcher.
	// This is because the device detection requires self (Cilium)Node object,
	// and the k8s service watcher depends on option.Config.EnableNodePort flag
	// which can be modified after the device detection.
	detectNativeDevices(isKubeProxyReplacementStrict)
	finishKubeProxyReplacementInit(isKubeProxyReplacementStrict)

	// BPF masquerade depends on BPF NodePort and require host-reachable svc to
	// be fully enabled in the tunneling mode, so the following checks should
	// happen after invoking initKubeProxyReplacementOptions().
	if option.Config.Masquerade && option.Config.EnableBPFMasquerade &&
		(!option.Config.EnableNodePort || option.Config.EgressMasqueradeInterfaces != "" ||
			(option.Config.Tunnel != option.TunnelDisabled && !hasFullHostReachableServices())) {

		var msg string
		switch {
		case !option.Config.EnableNodePort:
			msg = fmt.Sprintf("BPF masquerade requires NodePort (--%s=\"true\").",
				option.EnableNodePort)
		// Remove the check after https://github.com/cilium/cilium/issues/12544 is fixed
		case option.Config.Tunnel != option.TunnelDisabled && !hasFullHostReachableServices():
			msg = fmt.Sprintf("BPF masquerade requires --%s to be fully enabled (TCP and UDP).",
				option.EnableHostReachableServices)
		case option.Config.EgressMasqueradeInterfaces != "":
			msg = fmt.Sprintf("BPF masquerade does not allow to specify devices via --%s (use --%s instead).",
				option.EgressMasqueradeInterfaces, option.Devices)
		}
		// ipt.InstallRules() (called by Reinitialize()) happens later than
		// this  statement, so it's OK to fallback to iptables-based MASQ.
		option.Config.EnableBPFMasquerade = false
		log.Warn(msg + " Falling back to iptables-based masquerading.")
	}
	if option.Config.Masquerade && option.Config.EnableBPFMasquerade {
		// TODO(brb) nodeport + ipvlan constraints will be lifted once the SNAT BPF code has been refactored
		if option.Config.DatapathMode == datapathOption.DatapathModeIpvlan {
			log.Fatalf("BPF masquerade works only in veth mode (--%s=\"%s\"", option.DatapathMode, datapathOption.DatapathModeVeth)
		}
	} else if option.Config.EnableIPMasqAgent {
		log.Fatalf("BPF ip-masq-agent requires --%s=\"true\" and --%s=\"true\"", option.Masquerade, option.EnableBPFMasquerade)
	}
	if option.Config.EnableIPMasqAgent {
		if !option.Config.EnableIPv4 {
			log.Fatalf("BPF ip-masq-agent requires IPv4 support (--%s=\"true\")", option.EnableIPv4Name)
		}
		if !probe.HaveFullLPM() {
			log.Fatal("BPF ip-masq-agent needs kernel 4.16 or newer")
		}
	}
	if option.Config.EnableHostFirewall && len(option.Config.Devices) == 0 {
		device, err := linuxdatapath.NodeDeviceNameWithDefaultRoute()
		if err != nil {
			msg := "Host firewall's external facing device could not be determined. Use --%s to specify."
			log.WithError(err).Fatalf(msg, option.Devices)
		}
		log.WithField(logfields.Interface, device).
			Info("Using auto-derived device for host firewall")
		option.Config.Devices = []string{device}
	}

	d.k8sCachesSynced = d.k8sWatcher.InitK8sSubsystem()

	bootstrapStats.cleanup.Start()
	err = clearCiliumVeths()
	bootstrapStats.cleanup.EndError(err)
	if err != nil {
		log.WithError(err).Warning("Unable to clean stale endpoint interfaces")
	}

	d.bootstrapIPAM()

	// Start the proxy before we restore endpoints so that we can inject the
	// daemon's proxy into each endpoint.
	bootstrapStats.proxyStart.Start()
	// FIXME: Make the port range configurable.
	if option.Config.EnableL7Proxy {
		d.l7Proxy = proxy.StartProxySupport(10000, 20000, option.Config.RunDir,
			&d, option.Config.AgentLabels, d.datapath, d.endpointManager)
	} else {
		log.Info("L7 proxies are disabled")
	}
	bootstrapStats.proxyStart.End(true)

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
			logfields.V6Prefix:       node.GetIPv6AllocRange(),
			logfields.V4HealthIP:     d.nodeDiscovery.LocalNode.IPv4HealthIP,
			logfields.V6HealthIP:     d.nodeDiscovery.LocalNode.IPv6HealthIP,
			logfields.V4CiliumHostIP: node.GetInternalIPv4(),
			logfields.V6CiliumHostIP: node.GetIPv6Router(),
		}).Info("Annotating k8s node")

		err := k8s.Client().AnnotateNode(nodeTypes.GetName(),
			encryptKeyID,
			node.GetIPv4AllocRange(), node.GetIPv6AllocRange(),
			d.nodeDiscovery.LocalNode.IPv4HealthIP, d.nodeDiscovery.LocalNode.IPv6HealthIP,
			node.GetInternalIPv4(), node.GetIPv6Router())
		if err != nil {
			log.WithError(err).Warning("Cannot annotate k8s node with CIDR range")
		}
		bootstrapStats.k8sInit.End(true)
	} else if !option.Config.AnnotateK8sNode {
		log.Debug("Annotate k8s node is disabled.")
	}

	d.nodeDiscovery.StartDiscovery(nodeTypes.GetName())

	// Trigger refresh and update custom resource in the apiserver with all restored endpoints.
	// Trigger after nodeDiscovery.StartDiscovery to avoid custom resource update conflict.
	if option.Config.IPAM == ipamOption.IPAMCRD || option.Config.IPAM == ipamOption.IPAMENI || option.Config.IPAM == ipamOption.IPAMAzure {
		if option.Config.EnableIPv6 {
			d.ipam.IPv6Allocator.RestoreFinished()
		}
		if option.Config.EnableIPv4 {
			d.ipam.IPv4Allocator.RestoreFinished()
		}
	}

	// This needs to be done after the node addressing has been configured
	// as the node address is required as suffix.
	// well known identities have already been initialized above.
	// Ignore the channel returned by this function, as we want the global
	// identity allocator to run asynchronously.
	d.identityAllocator.InitIdentityAllocator(k8s.CiliumClient(), nil)

	d.bootstrapClusterMesh(nodeMngr)

	bootstrapStats.bpfBase.Start()
	err = d.init()
	bootstrapStats.bpfBase.EndError(err)
	if err != nil {
		log.WithError(err).Error("Error while initializing daemon")
		return nil, restoredEndpoints, err
	}

	// We can only start monitor agent once cilium_event has been set up.
	if option.Config.RunMonitorAgent {
		monitorAgent, err := monitoragent.NewAgent(d.ctx, defaults.MonitorBufferPages)
		if err != nil {
			return nil, nil, err
		}
		d.monitorAgent = monitorAgent

		if option.Config.EnableMonitor {
			err = monitoragent.ServeMonitorAPI(monitorAgent)
			if err != nil {
				return nil, nil, err
			}
		}
	}

	if err := d.syncEndpointsAndHostIPs(); err != nil {
		return nil, nil, err
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
			Context:     d.ctx,
		})

	if err := loader.RestoreTemplates(option.Config.StateDir); err != nil {
		log.WithError(err).Error("Unable to restore previous BPF templates")
	}

	// Start watcher for endpoint IP --> identity mappings in key-value store.
	// this needs to be done *after* init() for the daemon in that function,
	// we populate the IPCache with the host's IP(s).
	ipcache.InitIPIdentityWatcher()
	identitymanager.Subscribe(d.policy)

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

// WithDefaultEndpointManager creates the default endpoint manager with a
// functional endpoint synchronizer.
func WithDefaultEndpointManager() *endpointmanager.EndpointManager {
	return WithCustomEndpointManager(&watchers.EndpointSynchronizer{})
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
				Name:                  "clustermesh",
				ConfigDirectory:       path,
				NodeKeyCreator:        nodeStore.KeyCreator,
				ServiceMerger:         &d.k8sWatcher.K8sSvcCache,
				NodeManager:           nodeMngr,
				RemoteIdentityWatcher: d.identityAllocator,
			})
			if err != nil {
				log.WithError(err).Fatal("Unable to initialize ClusterMesh")
			}

			d.clustermesh = clustermesh
		}
	}
	bootstrapStats.clusterMeshInit.End(true)
}

// Close shuts down a daemon
func (d *Daemon) Close() {
	if d.policyTrigger != nil {
		d.policyTrigger.Shutdown()
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
		ip = node.GetExternalIPv4()
	case option.Config.EnableIPv6:
		ip = node.GetIPv6()
	}

	if ip == nil {
		log.Fatal("Node IP not available yet")
	}

	return ip.String()
}
