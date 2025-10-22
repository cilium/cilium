// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"sync"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	linuxdatapath "github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/debug"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	policyAPI "github.com/cilium/cilium/pkg/policy/api"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

const (
	// AutoCIDR indicates that a CIDR should be allocated
	AutoCIDR = "auto"
)

func initNodeLocalRoutingRule(params daemonParams) error {
	if !option.Config.DryMode {
		if option.Config.EnableL7Proxy {
			if err := linuxdatapath.NodeEnsureLocalRoutingRule(); err != nil {
				return fmt.Errorf("ensuring local routing rule: %w", err)
			}
		}
	}
	return nil
}

func configureDaemon(ctx context.Context, cleaner *daemonCleanup, params daemonParams) error {
	var err error

	bootstrapStats.daemonInit.Start()

	// WireGuard and IPSec are mutually exclusive.
	if params.IPsecAgent.Enabled() && params.WGAgent.Enabled() {
		return fmt.Errorf("WireGuard (--%s) cannot be used with IPsec (--%s)", wgTypes.EnableWireguard, datapath.EnableIPSec)
	}

	if !params.IPSecConfig.DNSProxyInsecureSkipTransparentModeCheckEnabled() {
		if params.IPsecAgent.Enabled() && option.Config.EnableL7Proxy && !option.Config.DNSProxyEnableTransparentMode {
			return fmt.Errorf("IPSec requires DNS proxy transparent mode to be enabled (--dnsproxy-enable-transparent-mode=\"true\")")
		}
	}

	if params.IPsecAgent.Enabled() && option.Config.TunnelingEnabled() {
		if err := ipsec.ProbeXfrmStateOutputMask(); err != nil {
			return fmt.Errorf("IPSec with tunneling requires support for xfrm state output masks (Linux 4.19 or later): %w", err)
		}
	}

	if option.Config.EnableHostFirewall {
		if params.IPsecAgent.Enabled() {
			return fmt.Errorf("IPSec cannot be used with the host firewall.")
		}
	}

	if option.Config.LocalRouterIPv4 != "" || option.Config.LocalRouterIPv6 != "" {
		if params.IPsecAgent.Enabled() {
			return fmt.Errorf("Cannot specify %s or %s with %s.", option.LocalRouterIPv4, option.LocalRouterIPv6, datapath.EnableIPSec)
		}
	}

	if params.IPsecAgent.Enabled() || params.WGAgent.Enabled() {
		if !option.Config.EnableCiliumNodeCRD {
			return fmt.Errorf("CiliumNode CRD cannot be disabled when encryption is enabled with WireGuard (--%s) or IPsec (--%s)", wgTypes.EnableWireguard, datapath.EnableIPSec)
		}
	}

	// IPAMENI IPSec is configured from Reinitialize() to pull in devices
	// that may be added or removed at runtime.
	if params.IPsecAgent.Enabled() &&
		!option.Config.TunnelingEnabled() &&
		len(option.Config.EncryptInterface) == 0 &&
		// If devices are required, we don't look at the EncryptInterface, as we
		// don't load bpf_network in loader.reinitializeIPSec. Instead, we load
		// bpf_host onto physical devices as chosen by configuration.
		!option.Config.AreDevicesRequired(params.KPRConfig, params.WGAgent.Enabled(), params.IPsecAgent.Enabled()) &&
		option.Config.IPAM != ipamOption.IPAMENI {
		link, err := linuxdatapath.NodeDeviceNameWithDefaultRoute(params.Logger)
		if err != nil {
			return fmt.Errorf("Ipsec default interface lookup failed, consider \"encrypt-interface\" to manually configure interface. Err: %w", err)
		}
		option.Config.EncryptInterface = append(option.Config.EncryptInterface, link)
	}

	// Do the partial kube-proxy replacement initialization before creating BPF
	// maps. Otherwise, some maps might not be created (e.g. session affinity).
	// finishKubeProxyReplacementInit(), which is called later after the device
	// detection, might disable BPF NodePort and friends. But this is fine, as
	// the feature does not influence the decision which BPF maps should be
	// created.
	if err := params.KPRInitializer.InitKubeProxyReplacementOptions(); err != nil {
		params.Logger.Error("unable to initialize kube-proxy replacement options", logfields.Error, err)
		return fmt.Errorf("unable to initialize kube-proxy replacement options: %w", err)
	}

	ctmap.InitMapInfo(params.MetricsRegistry, option.Config.EnableIPv4, option.Config.EnableIPv6, params.KPRConfig.KubeProxyReplacement || option.Config.EnableBPFMasquerade)

	identity.IterateReservedIdentities(func(_ identity.NumericIdentity, _ *identity.Identity) {
		metrics.Identity.WithLabelValues(identity.ReservedIdentityType).Inc()
		metrics.IdentityLabelSources.WithLabelValues(labels.LabelSourceReserved).Inc()
	})

	// Collect CIDR identities from the "old" bpf ipcache and restore them
	// in to the metadata layer.
	if option.Config.RestoreState && !option.Config.DryMode {
		// this *must* be called before initMaps(), which will "hide"
		// the "old" ipcache.
		err := params.IdentityRestorer.RestoreLocalIdentities()
		if err != nil {
			params.Logger.Warn("Failed to restore existing identities from the previous ipcache. This may cause policy interruptions during restart.", logfields.Error, err)
		}
	}

	bootstrapStats.daemonInit.End(true)

	// Stop all endpoints (its goroutines) on exit.
	cleaner.cleanupFuncs.Add(func() {
		params.Logger.Info("Waiting for all endpoints' goroutines to be stopped.")
		var wg sync.WaitGroup

		eps := params.EndpointManager.GetEndpoints()
		wg.Add(len(eps))

		for _, ep := range eps {
			go func(ep *endpoint.Endpoint) {
				ep.Stop()
				wg.Done()
			}(ep)
		}

		wg.Wait()
		params.Logger.Info("All endpoints' goroutines stopped.")
	})

	// Open or create BPF maps.
	bootstrapStats.mapsInit.Start()
	err = initMaps(params)
	bootstrapStats.mapsInit.EndError(err)
	if err != nil {
		params.Logger.Error("error while opening/creating BPF maps", logfields.Error, err)
		return fmt.Errorf("error while opening/creating BPF maps: %w", err)
	}

	debug.RegisterStatusObject("ipam", params.IPAM)

	if option.Config.DNSPolicyUnloadOnShutdown {
		params.Logger.Debug(
			"Registering cleanup function to unload DNS policies due to option",
			logfields.Option, option.DNSPolicyUnloadOnShutdown,
		)

		// add to pre-cleanup funcs because this needs to run on graceful shutdown, but
		// before the relevant subystems are being shut down.
		cleaner.preCleanupFuncs.Add(func() {
			// Stop k8s watchers
			params.Logger.Info("Stopping k8s watcher")
			params.K8sWatcher.StopWatcher()

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
				params.Logger.Debug(
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

			params.Policy.Iterate(func(rule *policytypes.PolicyEntry) {
				_ = rule.L4.Iterate(removeL7DNSRules)
			})

			if !needsPolicyRegen {
				params.Logger.Info(
					"No policy recalculation needed to remove DNS rules due to option",
					logfields.Option, option.DNSPolicyUnloadOnShutdown,
				)
				return
			}

			// Bump revision to trigger policy recalculation
			params.Logger.Info(
				"Triggering policy recalculation to remove DNS rules due to option",
				logfields.Option, option.DNSPolicyUnloadOnShutdown,
			)
			params.Policy.BumpRevision()
			regenerationMetadata := &regeneration.ExternalRegenerationMetadata{
				Reason:            "unloading DNS rules on graceful shutdown",
				RegenerationLevel: regeneration.RegenerateWithoutDatapath,
			}
			wg := params.EndpointManager.RegenerateAllEndpoints(regenerationMetadata)
			wg.Wait()
			params.Logger.Info("All endpoints regenerated after unloading DNS rules on graceful shutdown")
		})
	}

	policyAPI.InitEntities(params.ClusterInfo.Name)

	bootstrapStats.restore.Start()
	// fetch old endpoints before k8s is configured.
	if err := params.EndpointRestorer.FetchOldEndpoints(ctx, option.Config.StateDir); err != nil {
		params.Logger.Error("Unable to read existing endpoints", logfields.Error, err)
	}
	bootstrapStats.restore.End(true)

	// Load cached information from restored endpoints in to FQDN NameManager and DNS proxies
	bootstrapStats.fqdn.Start()
	params.DNSNameManager.RestoreCache(params.EndpointRestorer.GetState().possible)
	params.DNSProxy.BootstrapFQDN(params.EndpointRestorer.GetState().possible)
	bootstrapStats.fqdn.End(true)

	if params.Clientset.IsEnabled() {
		bootstrapStats.k8sInit.Start()
		// Errors are handled inside WaitForCRDsToRegister. It will fatal on a
		// context deadline or if the context has been cancelled, the context's
		// error will be returned. Otherwise, it succeeded.
		if !option.Config.DryMode {
			_, err := params.CRDSyncPromise.Await(ctx)
			if err != nil {
				return err
			}
		}

		if option.Config.IPAM == ipamOption.IPAMClusterPool ||
			option.Config.IPAM == ipamOption.IPAMMultiPool {
			// Create the CiliumNode custom resource. This call will block until
			// the custom resource has been created
			params.NodeDiscovery.UpdateCiliumNodeResource()
		}

		if err := agentK8s.WaitForNodeInformation(ctx, params.Logger, params.Resources.LocalNode, params.Resources.LocalCiliumNode); err != nil {
			params.Logger.Error("unable to connect to get node spec from apiserver", logfields.Error, err)
			return fmt.Errorf("unable to connect to get node spec from apiserver: %w", err)
		}

		// Kubernetes demands that the localhost can always reach local
		// pods. Therefore unless the AllowLocalhost policy is set to a
		// specific mode, always allow localhost to reach local
		// endpoints.
		if option.Config.AllowLocalhost == option.AllowLocalhostAuto {
			option.Config.AllowLocalhost = option.AllowLocalhostAlways
			params.Logger.Info("k8s mode: Allowing localhost to reach local endpoints")
		}

		bootstrapStats.k8sInit.End(true)
	}

	// The kube-proxy replacement and host-fw devices detection should happen after
	// establishing a connection to kube-apiserver, but before starting a k8s watcher.
	// This is because the device detection requires self (Cilium)Node object.

	rxn := params.DB.ReadTxn()
	drdName := ""
	directRoutingDevice, _ := params.DirectRoutingDevice.Get(ctx, rxn)
	if directRoutingDevice == nil {
		if option.Config.AreDevicesRequired(params.KPRConfig, params.WGAgent.Enabled(), params.IPsecAgent.Enabled()) {
			// Fail hard if devices are required to function.
			return fmt.Errorf("unable to determine direct routing device. Use --%s to specify it", option.DirectRoutingDevice)
		}
	} else {
		drdName = directRoutingDevice.Name
		params.Logger.Info(
			"Direct routing device detected",
			option.DirectRoutingDevice, drdName,
		)
	}

	nativeDevices, _ := datapathTables.SelectedDevices(params.Devices, rxn)
	if err := params.KPRInitializer.FinishKubeProxyReplacementInit(nativeDevices, drdName); err != nil {
		params.Logger.Error("failed to finalise LB initialization", logfields.Error, err)
		return fmt.Errorf("failed to finalise LB initialization: %w", err)
	}

	// BPF masquerade depends on BPF NodePort, so the following checks should
	// happen after invoking initKubeProxyReplacementOptions().
	if option.Config.MasqueradingEnabled() && option.Config.EnableBPFMasquerade {

		var err error
		switch {
		case len(option.Config.MasqueradeInterfaces) > 0:
			err = fmt.Errorf("BPF masquerade does not allow to specify devices via --%s (use --%s instead)",
				option.MasqueradeInterfaces, option.Devices)
		}
		if err != nil {
			params.Logger.Error("unable to initialize BPF masquerade support", logfields.Error, err)
			return fmt.Errorf("unable to initialize BPF masquerade support: %w", err)
		}
		if option.Config.EnableMasqueradeRouteSource {
			params.Logger.Error("BPF masquerading does not yet support masquerading to source IP from routing layer")
			return fmt.Errorf("BPF masquerading to route source (--%s=\"true\") currently not supported with BPF-based masquerading (--%s=\"true\")", option.EnableMasqueradeRouteSource, option.EnableBPFMasquerade)
		}
	} else if option.Config.EnableIPMasqAgent {
		params.Logger.Error(
			fmt.Sprintf("BPF ip-masq-agent requires (--%s=\"true\" or --%s=\"true\") and --%s=\"true\"", option.EnableIPv4Masquerade, option.EnableIPv6Masquerade, option.EnableBPFMasquerade),
			logfields.Error, err,
		)
		return fmt.Errorf("BPF ip-masq-agent requires (--%s=\"true\" or --%s=\"true\") and --%s=\"true\"", option.EnableIPv4Masquerade, option.EnableIPv6Masquerade, option.EnableBPFMasquerade)
	} else if !option.Config.MasqueradingEnabled() && option.Config.EnableBPFMasquerade {
		params.Logger.Error("IPv4 and IPv6 masquerading are both disabled, BPF masquerading requires at least one to be enabled")
		return fmt.Errorf("BPF masquerade requires (--%s=\"true\" or --%s=\"true\")", option.EnableIPv4Masquerade, option.EnableIPv6Masquerade)
	}
	if len(nativeDevices) == 0 {
		if option.Config.EnableHostFirewall {
			const msg = "Host firewall's external facing device could not be determined. Use --%s to specify."
			params.Logger.Error(
				fmt.Sprintf(msg, option.Devices),
				logfields.Error, err,
			)
			return fmt.Errorf(msg, option.Devices)
		}
	}

	// Some of the k8s watchers rely on option flags set above (specifically
	// EnableBPFMasquerade), so we should only start them once the flag values
	// are set.
	if params.Clientset.IsEnabled() {
		bootstrapStats.k8sInit.Start()

		// Launch the K8s watchers in parallel as we continue to process other
		// daemon options.
		params.K8sWatcher.InitK8sSubsystem(ctx, params.CacheStatus)
		bootstrapStats.k8sInit.End(true)
	} else {
		close(params.CacheStatus)
	}

	bootstrapStats.cleanup.Start()
	err = clearCiliumVeths(params.Logger)
	bootstrapStats.cleanup.EndError(err)
	if err != nil {
		params.Logger.Warn("Unable to clean stale endpoint interfaces", logfields.Error, err)
	}

	// Fetch the router (`cilium_host`) IPs in case they were set a priori from
	// the Kubernetes or CiliumNode resource in the K8s subsystem from call
	// k8s.WaitForNodeInformation(). These will be used later after starting
	// IPAM initialization to finish off the `cilium_host` IP restoration.
	var restoredRouterIPs restoredIPs
	restoredRouterIPs.IPv4FromK8s, restoredRouterIPs.IPv6FromK8s = node.GetInternalIPv4Router(params.Logger), node.GetIPv6Router(params.Logger)
	// Fetch the router IPs from the filesystem in case they were set a priori
	restoredRouterIPs.IPv4FromFS, restoredRouterIPs.IPv6FromFS = node.ExtractCiliumHostIPFromFS(params.Logger)

	// Configure and start IPAM without using the configuration yet.
	configureAndStartIPAM(ctx, params)

	bootstrapStats.restore.Start()
	// restore endpoints before any IPs are allocated to avoid eventual IP
	// conflicts later on, otherwise any IP conflict will result in the
	// endpoint not being able to be restored.
	err = params.EndpointRestorer.RestoreOldEndpoints()
	bootstrapStats.restore.EndError(err)
	if err != nil {
		return err
	}

	// We must do this after IPAM because we must wait until the
	// K8s resources have been synced.
	if err := params.InfraIPAllocator.AllocateIPs(ctx, restoredRouterIPs); err != nil { // will log errors/fatal internally
		return err
	}

	// Must occur after d.allocateIPs(), see GH-14245 and its fix.
	if option.Config.EnableCiliumNodeCRD {
		params.NodeDiscovery.StartDiscovery(ctx)
	}

	// Annotation of the k8s node must happen after discovery of the
	// PodCIDR range and allocation of the health IPs.
	if params.Clientset.IsEnabled() && option.Config.AnnotateK8sNode {
		bootstrapStats.k8sInit.Start()
		params.Logger.Info("Annotating k8s node",
			logfields.V4Prefix, node.GetIPv4AllocRange(params.Logger),
			logfields.V6Prefix, node.GetIPv6AllocRange(params.Logger),
			logfields.V4HealthIP, node.GetEndpointHealthIPv4(params.Logger),
			logfields.V6HealthIP, node.GetEndpointHealthIPv6(params.Logger),
			logfields.V4IngressIP, node.GetIngressIPv4(params.Logger),
			logfields.V6IngressIP, node.GetIngressIPv6(params.Logger),
			logfields.V4CiliumHostIP, node.GetInternalIPv4Router(params.Logger),
			logfields.V6CiliumHostIP, node.GetIPv6Router(params.Logger),
		)

		latestLocalNode, err := params.LocalNodeStore.Get(ctx)
		if err == nil {
			_, err = k8s.AnnotateNode(
				params.Logger,
				params.Clientset,
				nodeTypes.GetName(),
				latestLocalNode.Node,
				params.IPsecAgent.SPI())
		}
		if err != nil {
			params.Logger.Warn("Cannot annotate k8s node with CIDR range", logfields.Error, err)
		}

		bootstrapStats.k8sInit.End(true)
	} else if !option.Config.AnnotateK8sNode {
		params.Logger.Debug("Annotate k8s node is disabled.")
	}

	// Trigger refresh and update custom resource in the apiserver with all restored endpoints.
	// Trigger after nodeDiscovery.StartDiscovery to avoid custom resource update conflict.
	if option.Config.EnableIPv6 {
		params.IPAM.IPv6Allocator.RestoreFinished()
	}
	if option.Config.EnableIPv4 {
		params.IPAM.IPv4Allocator.RestoreFinished()
	}

	// This needs to be done after the node addressing has been configured
	// as the node address is required as suffix.
	// well known identities have already been initialized above.
	// Ignore the channel returned by this function, as we want the global
	// identity allocator to run asynchronously.
	if option.Config.IdentityAllocationMode != option.IdentityAllocationModeCRD ||
		params.Clientset.IsEnabled() {
		// **NOTE** The global identity allocator is not yet initialized here; that
		// happens below via InitIdentityAllocator(). Only the local identity
		// allocator is initialized up until here.
		realIdentityAllocator := params.IdentityAllocator
		realIdentityAllocator.InitIdentityAllocator(params.Clientset, params.KVStoreClient)
	}

	// Must be done at least after initializing BPF LB-related maps
	// (lbmap.Init()).
	bootstrapStats.bpfBase.Start()
	err = initNodeLocalRoutingRule(params)
	bootstrapStats.bpfBase.EndError(err)
	if err != nil {
		return fmt.Errorf("error while initializing daemon: %w", err)
	}

	// Start the host IP synchronization. Blocks until the initial synchronization
	// has finished.
	if err := params.SyncHostIPs.StartAndWaitFirst(ctx); err != nil {
		return err
	}

	// Start watcher for endpoint IP --> identity mappings in key-value store.
	// this needs to be done *after* that the ipcache map has been recreated
	// by initMaps.
	if params.IPIdentityWatcher.IsEnabled() {
		go func() {
			params.Logger.Info("Starting IP identity watcher")
			params.IPIdentityWatcher.Watch(ctx)
		}()
	}

	if err := params.IPsecAgent.StartBackgroundJobs(params.NodeHandler); err != nil {
		params.Logger.Error("Unable to start IPsec key watcher", logfields.Error, err)
	}

	return nil
}
