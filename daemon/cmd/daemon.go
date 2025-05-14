// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/vishvananda/netlink"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/controller"
	linuxdatapath "github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/debug"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointcreator "github.com/cilium/cilium/pkg/endpoint/creator"
	endpointmetadata "github.com/cilium/cilium/pkg/endpoint/metadata"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/health"
	"github.com/cilium/cilium/pkg/identity"
	identitycell "github.com/cilium/cilium/pkg/identity/cache/cell"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	identityrestoration "github.com/cilium/cilium/pkg/identity/restoration"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/legacy/redirectpolicy"
	"github.com/cilium/cilium/pkg/loadbalancer/legacy/service"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/metrics"
	monitoragent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	policyAPI "github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/resiliency"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// AutoCIDR indicates that a CIDR should be allocated
	AutoCIDR = "auto"
)

// Daemon is the cilium daemon that is in charge of perform all necessary plumbing,
// monitoring when a LXC starts.
type Daemon struct {
	ctx             context.Context
	logger          *slog.Logger
	metricsRegistry *metrics.Registry
	clientset       k8sClient.Clientset
	db              *statedb.DB
	svc             service.ServiceManager
	policy          policy.PolicyRepository
	idmgr           identitymanager.IDManager

	monitorAgent monitoragent.Agent

	directRoutingDev datapathTables.DirectRoutingDevice
	routes           statedb.Table[*datapathTables.Route]
	devices          statedb.Table[*datapathTables.Device]
	nodeAddrs        statedb.Table[datapathTables.NodeAddress]

	clustermesh *clustermesh.ClusterMesh

	mtuConfig mtu.MTU

	nodeAddressing datapath.NodeAddressing

	// nodeDiscovery defines the node discovery logic of the agent
	nodeDiscovery  *nodediscovery.NodeDiscovery
	nodeLocalStore *node.LocalNodeStore

	// ipam is the IP address manager of the agent
	ipam *ipam.IPAM

	endpointCreator endpointcreator.EndpointCreator
	endpointManager endpointmanager.EndpointManager

	endpointRestoreComplete       chan struct{}
	endpointInitialPolicyComplete chan struct{}

	identityAllocator identitycell.CachingIdentityAllocator
	identityRestorer  *identityrestoration.LocalIdentityRestorer
	ipcache           *ipcache.IPCache

	k8sWatcher  *watchers.K8sWatcher
	k8sSvcCache k8s.ServiceCache

	endpointMetadata endpointmetadata.EndpointMetadataFetcher

	// healthEndpointRouting is the information required to set up the health
	// endpoint's routing in ENI or Azure IPAM mode
	healthEndpointRouting *linuxrouting.RoutingInfo

	ciliumHealth health.CiliumHealthManager

	// Controllers owned by the daemon
	controllers *controller.Manager
	jobGroup    job.Group

	bwManager datapath.BandwidthManager

	lrpManager   *redirectpolicy.Manager
	maglevConfig maglev.Config

	lbConfig loadbalancer.Config
}

func (d *Daemon) init() error {
	if !option.Config.DryMode {
		if option.Config.EnableL7Proxy {
			if err := linuxdatapath.NodeEnsureLocalRoutingRule(); err != nil {
				return fmt.Errorf("ensuring local routing rule: %w", err)
			}
		}
	}
	return nil
}

// removeOldRouterState will try to ensure that the only IP assigned to the
// `cilium_host` interface is the given restored IP. If the given IP is nil,
// then it attempts to clear all IPs from the interface.
func removeOldRouterState(logger *slog.Logger, ipv6 bool, restoredIP net.IP) error {
	l, err := safenetlink.LinkByName(defaults.HostDevice)
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		// There's no old state remove as the host device doesn't exist.
		// This is always the case when the agent is started for the first time.
		return nil
	}
	if err != nil {
		return resiliency.Retryable(err)
	}

	family := netlink.FAMILY_V4
	if ipv6 {
		family = netlink.FAMILY_V6
	}
	addrs, err := safenetlink.AddrList(l, family)
	if err != nil {
		return resiliency.Retryable(err)
	}

	isRestoredIP := func(a netlink.Addr) bool {
		return restoredIP != nil && restoredIP.Equal(a.IP)
	}
	if len(addrs) == 0 || (len(addrs) == 1 && isRestoredIP(addrs[0])) {
		return nil // nothing to clean up
	}

	logger.Info("More than one stale router IP was found on the cilium_host device after restoration, cleaning up old router IPs.")

	for _, a := range addrs {
		if isRestoredIP(a) {
			continue
		}
		logger.Debug(
			"Removing stale router IP from cilium_host device",
			logfields.IPAddr, a.IP,
		)
		if e := netlink.AddrDel(l, &a); e != nil {
			err = errors.Join(err, resiliency.Retryable(fmt.Errorf("failed to remove IP %s: %w", a.IP, e)))
		}
	}

	return err
}

// removeOldCiliumHostIPs calls removeOldRouterState() for both IPv4 and IPv6
// in a retry loop.
func (d *Daemon) removeOldCiliumHostIPs(ctx context.Context, restoredRouterIPv4, restoredRouterIPv6 net.IP) {
	gcHostIPsFn := func(ctx context.Context, retries int) (done bool, err error) {
		var errs error
		if option.Config.EnableIPv4 {
			errs = errors.Join(errs, removeOldRouterState(d.logger, false, restoredRouterIPv4))
		}
		if option.Config.EnableIPv6 {
			errs = errors.Join(errs, removeOldRouterState(d.logger, true, restoredRouterIPv6))
		}
		if resiliency.IsRetryable(errs) && !errors.As(errs, &netlink.LinkNotFoundError{}) {
			d.logger.Warn(
				"Failed to remove old router IPs from cilium_host.",
				logfields.Error, errs,
				logfields.Attempt, retries,
			)
			return false, nil
		}
		return true, errs
	}
	if err := resiliency.Retry(ctx, 100*time.Millisecond, 3, gcHostIPsFn); err != nil {
		d.logger.Error("Restore of the cilium_host ips failed. Manual intervention is required to remove all other old IPs.", logfields.Error, err)
	}
}

// newDaemon creates and returns a new Daemon with the parameters set in c.
func newDaemon(ctx context.Context, cleaner *daemonCleanup, params *daemonParams) (*Daemon, *endpointRestoreState, error) {
	var err error

	bootstrapStats.daemonInit.Start()

	// EncryptedOverlay feature must check the TunnelProtocol if enabled, since
	// it only supports VXLAN right now.
	if option.Config.EncryptionEnabled() && option.Config.EnableIPSecEncryptedOverlay {
		if !option.Config.TunnelingEnabled() {
			return nil, nil, fmt.Errorf("EncryptedOverlay support requires VXLAN tunneling mode")
		}
		if params.TunnelConfig.EncapProtocol() != tunnel.VXLAN {
			return nil, nil, fmt.Errorf("EncryptedOverlay support requires VXLAN tunneling protocol")
		}
	}

	if option.Config.TunnelingEnabled() && params.TunnelConfig.UnderlayProtocol() == tunnel.IPv6 {
		if option.Config.EnableWireguard {
			return nil, nil, fmt.Errorf("WireGuard requires an IPv4 underlay")
		}
	}

	// Check the kernel if we can make use of managed neighbor entries which
	// simplifies and fully 'offloads' L2 resolution handling to the kernel.
	if !option.Config.DryMode {
		if err := probes.HaveManagedNeighbors(params.Logger); err == nil {
			params.Logger.Info("Using Managed Neighbor Kernel support")
			option.Config.ARPPingKernelManaged = true
		}
	}

	// Do the partial kube-proxy replacement initialization before creating BPF
	// maps. Otherwise, some maps might not be created (e.g. session affinity).
	// finishKubeProxyReplacementInit(), which is called later after the device
	// detection, might disable BPF NodePort and friends. But this is fine, as
	// the feature does not influence the decision which BPF maps should be
	// created.
	if err := initKubeProxyReplacementOptions(params.Logger, params.Sysctl, params.TunnelConfig, params.LBConfig); err != nil {
		params.Logger.Error("unable to initialize kube-proxy replacement options", logfields.Error, err)
		return nil, nil, fmt.Errorf("unable to initialize kube-proxy replacement options: %w", err)
	}

	ctmap.InitMapInfo(params.MetricsRegistry, option.Config.EnableIPv4, option.Config.EnableIPv6, option.Config.EnableNodePort)

	lbmapInitParams := lbmap.InitParams{
		IPv4: option.Config.EnableIPv4,
		IPv6: option.Config.EnableIPv6,

		MaxSockRevNatMapEntries:  params.LBConfig.LBSockRevNatEntries,
		ServiceMapMaxEntries:     params.LBConfig.LBServiceMapEntries,
		BackEndMapMaxEntries:     params.LBConfig.LBBackendMapEntries,
		RevNatMapMaxEntries:      params.LBConfig.LBRevNatEntries,
		AffinityMapMaxEntries:    params.LBConfig.LBAffinityMapEntries,
		SourceRangeMapMaxEntries: params.LBConfig.LBSourceRangeMapEntries,
		MaglevMapMaxEntries:      params.LBConfig.LBMaglevMapEntries,
	}
	lbmap.Init(params.MetricsRegistry, lbmapInitParams)

	identity.IterateReservedIdentities(func(_ identity.NumericIdentity, _ *identity.Identity) {
		metrics.Identity.WithLabelValues(identity.ReservedIdentityType).Inc()
		metrics.IdentityLabelSources.WithLabelValues(labels.LabelSourceReserved).Inc()
	})

	d := Daemon{
		ctx:              ctx,
		logger:           params.Logger,
		metricsRegistry:  params.MetricsRegistry,
		clientset:        params.Clientset,
		db:               params.DB,
		mtuConfig:        params.MTU,
		directRoutingDev: params.DirectRoutingDevice,
		nodeAddressing:   params.NodeAddressing,
		routes:           params.Routes,
		devices:          params.Devices,
		nodeAddrs:        params.NodeAddrs,
		nodeDiscovery:    params.NodeDiscovery,
		nodeLocalStore:   params.LocalNodeStore,
		controllers:      controller.NewManager(),
		jobGroup:         params.JobGroup,

		// **NOTE** The global identity allocator is not yet initialized here; that
		// happens below via InitIdentityAllocator(). Only the local identity
		// allocator is initialized here.
		identityAllocator: params.IdentityAllocator,
		ipcache:           params.IPCache,
		identityRestorer:  params.IdentityRestorer,
		policy:            params.Policy,
		idmgr:             params.IdentityManager,
		clustermesh:       params.ClusterMesh,
		monitorAgent:      params.MonitorAgent,
		svc:               params.ServiceManager,
		bwManager:         params.BandwidthManager,
		endpointCreator:   params.EndpointCreator,
		endpointManager:   params.EndpointManager,
		endpointMetadata:  params.EndpointMetadata,
		k8sWatcher:        params.K8sWatcher,
		k8sSvcCache:       params.K8sSvcCache,
		ipam:              params.IPAM,
		lrpManager:        params.LRPManager,
		maglevConfig:      params.MaglevConfig,
		lbConfig:          params.LBConfig,
		ciliumHealth:      params.CiliumHealth,
	}

	// initialize endpointRestoreComplete channel as soon as possible so that subsystems
	// can wait on it to get closed and not block forever if they happen so start
	// waiting when it is not yet initialized (which causes them to block forever).
	if option.Config.RestoreState {
		d.endpointRestoreComplete = make(chan struct{})
		d.endpointInitialPolicyComplete = make(chan struct{})
	}

	// Collect CIDR identities from the "old" bpf ipcache and restore them
	// in to the metadata layer.
	if option.Config.RestoreState && !option.Config.DryMode {
		// this *must* be called before initMaps(), which will "hide"
		// the "old" ipcache.
		err := d.identityRestorer.RestoreLocalIdentities()
		if err != nil {
			d.logger.Warn("Failed to restore existing identities from the previous ipcache. This may cause policy interruptions during restart.", logfields.Error, err)
		}
	}

	bootstrapStats.daemonInit.End(true)

	// Stop all endpoints (its goroutines) on exit.
	cleaner.cleanupFuncs.Add(func() {
		d.logger.Info("Waiting for all endpoints' goroutines to be stopped.")
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
		d.logger.Info("All endpoints' goroutines stopped.")
	})

	// Open or create BPF maps.
	bootstrapStats.mapsInit.Start()
	err = d.initMaps()
	bootstrapStats.mapsInit.EndError(err)
	if err != nil {
		d.logger.Error("error while opening/creating BPF maps", logfields.Error, err)
		return nil, nil, fmt.Errorf("error while opening/creating BPF maps: %w", err)
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
			d.logger.Warn("Failed to restore services from BPF maps", logfields.Error, err)
		}
		bootstrapStats.restore.End(true)
	}

	debug.RegisterStatusObject("k8s-service-cache", d.k8sSvcCache)
	debug.RegisterStatusObject("ipam", d.ipam)

	d.k8sWatcher.RunK8sServiceHandler()

	if option.Config.DNSPolicyUnloadOnShutdown {
		d.logger.Debug(
			"Registering cleanup function to unload DNS policies due to option",
			logfields.Option, option.DNSPolicyUnloadOnShutdown,
		)

		// add to pre-cleanup funcs because this needs to run on graceful shutdown, but
		// before the relevant subystems are being shut down.
		cleaner.preCleanupFuncs.Add(func() {
			// Stop k8s watchers
			d.logger.Info("Stopping k8s watcher")
			d.k8sWatcher.StopWatcher()

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
				d.logger.Debug(
					"Found egress L7 DNS rules",
					logfields.PortProtocol, portProtocols[0],
					logfields.DNSRules, dnsRules,
				)

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

			d.policy.Iterate(func(rule *policyAPI.Rule) {
				for _, er := range rule.Egress {
					_ = er.ToPorts.Iterate(removeL7DNSRules)
				}
			})

			if !needsPolicyRegen {
				d.logger.Info(
					"No policy recalculation needed to remove DNS rules due to option",
					logfields.Option, option.DNSPolicyUnloadOnShutdown,
				)
				return
			}

			// Bump revision to trigger policy recalculation
			d.logger.Info(
				"Triggering policy recalculation to remove DNS rules due to option",
				logfields.Option, option.DNSPolicyUnloadOnShutdown,
			)
			d.policy.BumpRevision()
			regenerationMetadata := &regeneration.ExternalRegenerationMetadata{
				Reason:            "unloading DNS rules on graceful shutdown",
				RegenerationLevel: regeneration.RegenerateWithoutDatapath,
			}
			wg := d.endpointManager.RegenerateAllEndpoints(regenerationMetadata)
			wg.Wait()
			d.logger.Info("All endpoints regenerated after unloading DNS rules on graceful shutdown")
		})
	}

	policyAPI.InitEntities(params.ClusterInfo.Name)

	bootstrapStats.restore.Start()
	// fetch old endpoints before k8s is configured.
	restoredEndpoints, err := d.fetchOldEndpoints(option.Config.StateDir)
	if err != nil {
		d.logger.Error("Unable to read existing endpoints", logfields.Error, err)
	}
	bootstrapStats.restore.End(true)

	// Load cached information from restored endpoints in to FQDN NameManager and DNS proxies
	bootstrapStats.fqdn.Start()
	params.DNSNameManager.RestoreCache(restoredEndpoints.possible)
	params.DNSProxy.BootstrapFQDN(restoredEndpoints.possible)
	bootstrapStats.fqdn.End(true)

	if params.Clientset.IsEnabled() {
		bootstrapStats.k8sInit.Start()
		// Errors are handled inside WaitForCRDsToRegister. It will fatal on a
		// context deadline or if the context has been cancelled, the context's
		// error will be returned. Otherwise, it succeeded.
		if !option.Config.DryMode {
			_, err := params.CRDSyncPromise.Await(d.ctx)
			if err != nil {
				return nil, restoredEndpoints, err
			}
		}

		if option.Config.IPAM == ipamOption.IPAMClusterPool ||
			option.Config.IPAM == ipamOption.IPAMMultiPool {
			// Create the CiliumNode custom resource. This call will block until
			// the custom resource has been created
			d.nodeDiscovery.UpdateCiliumNodeResource()
		}

		if err := agentK8s.WaitForNodeInformation(d.ctx, d.logger, params.Resources.LocalNode, params.Resources.LocalCiliumNode); err != nil {
			d.logger.Error("unable to connect to get node spec from apiserver", logfields.Error, err)
			return nil, nil, fmt.Errorf("unable to connect to get node spec from apiserver: %w", err)
		}

		// Kubernetes demands that the localhost can always reach local
		// pods. Therefore unless the AllowLocalhost policy is set to a
		// specific mode, always allow localhost to reach local
		// endpoints.
		if option.Config.AllowLocalhost == option.AllowLocalhostAuto {
			option.Config.AllowLocalhost = option.AllowLocalhostAlways
			d.logger.Info("k8s mode: Allowing localhost to reach local endpoints")
		}

		bootstrapStats.k8sInit.End(true)
	}

	if params.WGAgent != nil && option.Config.EnableWireguard {
		if err := params.WGAgent.Init(d.ipcache); err != nil {
			d.logger.Error("failed to initialize WireGuard agent", logfields.Error, err)
			return nil, nil, fmt.Errorf("failed to initialize WireGuard agent: %w", err)
		}

		params.NodeManager.Subscribe(params.WGAgent)
	}

	// The kube-proxy replacement and host-fw devices detection should happen after
	// establishing a connection to kube-apiserver, but before starting a k8s watcher.
	// This is because the device detection requires self (Cilium)Node object,
	// and the k8s service watcher depends on option.Config.EnableNodePort flag
	// which can be modified after the device detection.

	rxn := d.db.ReadTxn()
	drdName := ""
	directRoutingDevice, _ := params.DirectRoutingDevice.Get(ctx, rxn)
	if directRoutingDevice == nil {
		if option.Config.AreDevicesRequired() {
			// Fail hard if devices are required to function.
			return nil, nil, fmt.Errorf("unable to determine direct routing device. Use --%s to specify it",
				option.DirectRoutingDevice)
		}

		d.logger.Warn("failed to detect devices, disabling BPF NodePort", logfields.Error, err)
		disableNodePort()
	} else {
		drdName = directRoutingDevice.Name
		d.logger.Info(
			"Direct routing device detected",
			option.DirectRoutingDevice, drdName,
		)
	}

	nativeDevices, _ := datapathTables.SelectedDevices(d.devices, rxn)
	if err := finishKubeProxyReplacementInit(params.Logger, params.Sysctl, nativeDevices, drdName, d.lbConfig); err != nil {
		d.logger.Error("failed to finalise LB initialization", logfields.Error, err)
		return nil, nil, fmt.Errorf("failed to finalise LB initialization: %w", err)
	}

	// BPF masquerade depends on BPF NodePort, so the following checks should
	// happen after invoking initKubeProxyReplacementOptions().
	if option.Config.MasqueradingEnabled() && option.Config.EnableBPFMasquerade {

		var err error
		switch {
		case !option.Config.EnableNodePort:
			err = fmt.Errorf("BPF masquerade requires NodePort (--%s=\"true\")",
				option.EnableNodePort)
		case len(option.Config.MasqueradeInterfaces) > 0:
			err = fmt.Errorf("BPF masquerade does not allow to specify devices via --%s (use --%s instead)",
				option.MasqueradeInterfaces, option.Devices)
		}
		if err != nil {
			d.logger.Error("unable to initialize BPF masquerade support", logfields.Error, err)
			return nil, nil, fmt.Errorf("unable to initialize BPF masquerade support: %w", err)
		}
		if option.Config.EnableMasqueradeRouteSource {
			d.logger.Error("BPF masquerading does not yet support masquerading to source IP from routing layer")
			return nil, nil, fmt.Errorf("BPF masquerading to route source (--%s=\"true\") currently not supported with BPF-based masquerading (--%s=\"true\")", option.EnableMasqueradeRouteSource, option.EnableBPFMasquerade)
		}
	} else if option.Config.EnableIPMasqAgent {
		d.logger.Error(
			fmt.Sprintf("BPF ip-masq-agent requires (--%s=\"true\" or --%s=\"true\") and --%s=\"true\"", option.EnableIPv4Masquerade, option.EnableIPv6Masquerade, option.EnableBPFMasquerade),
			logfields.Error, err,
		)
		return nil, nil, fmt.Errorf("BPF ip-masq-agent requires (--%s=\"true\" or --%s=\"true\") and --%s=\"true\"", option.EnableIPv4Masquerade, option.EnableIPv6Masquerade, option.EnableBPFMasquerade)
	} else if !option.Config.MasqueradingEnabled() && option.Config.EnableBPFMasquerade {
		d.logger.Error("IPv4 and IPv6 masquerading are both disabled, BPF masquerading requires at least one to be enabled")
		return nil, nil, fmt.Errorf("BPF masquerade requires (--%s=\"true\" or --%s=\"true\")", option.EnableIPv4Masquerade, option.EnableIPv6Masquerade)
	}
	if len(nativeDevices) == 0 {
		if option.Config.EnableHostFirewall {
			const msg = "Host firewall's external facing device could not be determined. Use --%s to specify."
			d.logger.Error(
				fmt.Sprintf(msg, option.Devices),
				logfields.Error, err,
			)
			return nil, nil, fmt.Errorf(msg, option.Devices)
		}
	}

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
	err = clearCiliumVeths(d.logger)
	bootstrapStats.cleanup.EndError(err)
	if err != nil {
		d.logger.Warn("Unable to clean stale endpoint interfaces", logfields.Error, err)
	}

	// Must init kvstore before starting node discovery
	if option.Config.KVStore == "" {
		d.logger.Info("Skipping kvstore configuration")
	} else {
		bootstrapStats.kvstore.Start()
		d.initKVStore(params.ServiceResolver)
		bootstrapStats.kvstore.End(true)
	}

	// Fetch the router (`cilium_host`) IPs in case they were set a priori from
	// the Kubernetes or CiliumNode resource in the K8s subsystem from call
	// k8s.WaitForNodeInformation(). These will be used later after starting
	// IPAM initialization to finish off the `cilium_host` IP restoration.
	var restoredRouterIPs restoredIPs
	restoredRouterIPs.IPv4FromK8s, restoredRouterIPs.IPv6FromK8s = node.GetInternalIPv4Router(params.Logger), node.GetIPv6Router(params.Logger)
	// Fetch the router IPs from the filesystem in case they were set a priori
	restoredRouterIPs.IPv4FromFS, restoredRouterIPs.IPv6FromFS = node.ExtractCiliumHostIPFromFS(params.Logger)

	// Configure IPAM without using the configuration yet.
	d.configureIPAM()

	// Start IPAM
	d.startIPAM()

	bootstrapStats.restore.Start()
	// restore endpoints before any IPs are allocated to avoid eventual IP
	// conflicts later on, otherwise any IP conflict will result in the
	// endpoint not being able to be restored.
	d.restoreOldEndpoints(restoredEndpoints)
	bootstrapStats.restore.End(true)

	// We must do this after IPAM because we must wait until the
	// K8s resources have been synced.
	if err := d.allocateIPs(ctx, restoredRouterIPs); err != nil { // will log errors/fatal internally
		return nil, nil, err
	}

	// Must occur after d.allocateIPs(), see GH-14245 and its fix.
	d.nodeDiscovery.StartDiscovery()

	// Annotation of the k8s node must happen after discovery of the
	// PodCIDR range and allocation of the health IPs.
	if params.Clientset.IsEnabled() && option.Config.AnnotateK8sNode {
		bootstrapStats.k8sInit.Start()
		d.logger.Info("Annotating k8s node",
			logfields.V4Prefix, node.GetIPv4AllocRange(params.Logger),
			logfields.V6Prefix, node.GetIPv6AllocRange(params.Logger),
			logfields.V4HealthIP, node.GetEndpointHealthIPv4(params.Logger),
			logfields.V6HealthIP, node.GetEndpointHealthIPv6(params.Logger),
			logfields.V4IngressIP, node.GetIngressIPv4(params.Logger),
			logfields.V6IngressIP, node.GetIngressIPv6(params.Logger),
			logfields.V4CiliumHostIP, node.GetInternalIPv4Router(params.Logger),
			logfields.V6CiliumHostIP, node.GetIPv6Router(params.Logger),
		)

		latestLocalNode, err := d.nodeLocalStore.Get(ctx)
		if err == nil {
			_, err = k8s.AnnotateNode(
				d.logger,
				params.Clientset,
				nodeTypes.GetName(),
				latestLocalNode.Node,
				params.IPsecKeyCustodian.SPI())
		}
		if err != nil {
			d.logger.Warn("Cannot annotate k8s node with CIDR range", logfields.Error, err)
		}

		bootstrapStats.k8sInit.End(true)
	} else if !option.Config.AnnotateK8sNode {
		d.logger.Debug("Annotate k8s node is disabled.")
	}

	// Trigger refresh and update custom resource in the apiserver with all restored endpoints.
	// Trigger after nodeDiscovery.StartDiscovery to avoid custom resource update conflict.
	if option.Config.EnableIPv6 {
		d.ipam.IPv6Allocator.RestoreFinished()
	}
	if option.Config.EnableIPv4 {
		d.ipam.IPv4Allocator.RestoreFinished()
	}

	// This needs to be done after the node addressing has been configured
	// as the node address is required as suffix.
	// well known identities have already been initialized above.
	// Ignore the channel returned by this function, as we want the global
	// identity allocator to run asynchronously.
	if option.Config.IdentityAllocationMode != option.IdentityAllocationModeCRD ||
		params.Clientset.IsEnabled() {
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

	if option.Config.EnableVTEP {
		// Start controller to setup and periodically verify VTEP
		// endpoints and routes.
		syncVTEPControllerGroup := controller.NewGroup("sync-vtep")
		d.controllers.UpdateController(
			syncVTEPControllerGroup.Name,
			controller.ControllerParams{
				Group:       syncVTEPControllerGroup,
				DoFunc:      syncVTEP(d.logger, d.metricsRegistry),
				RunInterval: time.Minute,
				Context:     d.ctx,
			})
	}

	// Start the host IP synchronization. Blocks until the initial synchronization
	// has finished.
	if err := params.SyncHostIPs.StartAndWaitFirst(ctx); err != nil {
		return nil, nil, err
	}

	// Start watcher for endpoint IP --> identity mappings in key-value store.
	// this needs to be done *after* init() for the daemon in that function,
	// we populate the IPCache with the host's IP(s).
	if option.Config.KVStore != "" {
		go func() {
			d.logger.Info("Starting IP identity watcher")
			params.IPIdentityWatcher.Watch(ctx, kvstore.Client(), ipcache.WithSelfDeletionProtection(params.IPIdentitySyncer))
		}()
	}

	if err := params.IPsecKeyCustodian.StartBackgroundJobs(params.NodeHandler); err != nil {
		d.logger.Error("Unable to start IPsec key watcher", logfields.Error, err)
	}

	return &d, restoredEndpoints, nil
}

// Close shuts down a daemon
func (d *Daemon) Close() {
	d.idmgr.RemoveAll()

	// Ensures all controllers are stopped!
	d.controllers.RemoveAllAndWait()
}
