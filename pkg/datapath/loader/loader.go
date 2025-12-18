// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/datapath/config"
	routeReconciler "github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/callsmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	wgtypes "github.com/cilium/cilium/pkg/wireguard/types"
)

const (
	subsystem = "datapath-loader"

	symbolFromEndpoint = "cil_from_container"
	symbolToEndpoint   = "cil_to_container"
	symbolFromNetwork  = "cil_from_network"

	symbolFromHostNetdevEp = "cil_from_netdev"
	symbolToHostNetdevEp   = "cil_to_netdev"
	symbolFromHostEp       = "cil_from_host"
	symbolToHostEp         = "cil_to_host"

	symbolToWireguard   = "cil_to_wireguard"
	symbolFromWireguard = "cil_from_wireguard"

	symbolFromHostNetdevXDP = "cil_xdp_entry"

	symbolFromOverlay = "cil_from_overlay"
	symbolToOverlay   = "cil_to_overlay"

	dirIngress = "ingress"
	dirEgress  = "egress"
)

// loader is a wrapper structure around operations related to compiling,
// loading, and reloading datapath programs.
type loader struct {
	logger *slog.Logger

	// templateCache is the cache of pre-compiled datapaths. Only set after
	// a call to Reinitialize.
	templateCache *objectCache

	ipsecMu lock.Mutex // guards reinitializeIPSec

	hostDpInitializedOnce sync.Once
	hostDpInitialized     chan struct{}

	sysctl             sysctl.Sysctl
	prefilter          datapath.PreFilter
	compilationLock    datapath.CompilationLock
	configWriter       datapath.ConfigWriter
	nodeConfigNotifier *manager.NodeConfigNotifier

	db           *statedb.DB
	devices      statedb.Table[*tables.Device]
	routeManager *routeReconciler.DesiredRouteManager
}

type Params struct {
	cell.In

	JobGroup           job.Group
	Logger             *slog.Logger
	Sysctl             sysctl.Sysctl
	Prefilter          datapath.PreFilter
	CompilationLock    datapath.CompilationLock
	ConfigWriter       datapath.ConfigWriter
	NodeConfigNotifier *manager.NodeConfigNotifier
	RouteManager       *routeReconciler.DesiredRouteManager
	DB                 *statedb.DB
	Devices            statedb.Table[*tables.Device]
	EPRestorer         promise.Promise[endpointstate.Restorer]

	// Force map initialisation before loader. You should not use these otherwise.
	// Some of the entries in this slice may be nil.
	BpfMaps []bpf.BpfMap `group:"bpf-maps"`
}

// newLoader returns a new loader.
func newLoader(p Params) *loader {
	registerRouteInitializer(p)
	return &loader{
		logger:             p.Logger,
		templateCache:      newObjectCache(p.Logger, p.ConfigWriter, filepath.Join(option.Config.StateDir, defaults.TemplatesDir)),
		sysctl:             p.Sysctl,
		hostDpInitialized:  make(chan struct{}),
		prefilter:          p.Prefilter,
		compilationLock:    p.CompilationLock,
		configWriter:       p.ConfigWriter,
		nodeConfigNotifier: p.NodeConfigNotifier,
		routeManager:       p.RouteManager,

		db:      p.DB,
		devices: p.Devices,
	}
}

func registerRouteInitializer(p Params) {
	// [upsertEndpointRoute] Creates routes for endpoints that need per endpoint routes.
	// We need to tell the route reconciler to delay pruning of routes from the kernel until we have had a chance
	// to insert desired routes for all endpoints that need them.
	//
	// Use the endpoint restorer to get a signal when all existing endpoints have been restored, and thus
	// [loader.ReloadDatapath] has been called for all existing endpoints. After that we can finalize the route
	// initializer.
	routeInitializer := p.RouteManager.RegisterInitializer("per-endpoint-routes")
	p.JobGroup.Add(job.OneShot("per-endpoint-route-initializer", func(ctx context.Context, _ cell.Health) error {
		defer p.RouteManager.FinalizeInitializer(routeInitializer)

		epRestorer, err := p.EPRestorer.Await(ctx)
		if err != nil {
			return fmt.Errorf("waiting for endpoint restorer: %w", err)
		}

		if err := epRestorer.WaitForEndpointRestore(ctx); err != nil {
			return fmt.Errorf("waiting for endpoint restore: %w", err)
		}

		return nil
	}))
}

func upsertEndpointRoute(logger *slog.Logger, db *statedb.DB, devices statedb.Table[*tables.Device], rm *routeReconciler.DesiredRouteManager, ep datapath.Endpoint, ip netip.Prefix) error {
	owner, err := rm.GetOrRegisterOwner("endpoint/" + ep.StringID())
	if err != nil {
		return fmt.Errorf("getting or registering owner for endpoint %s: %w", ep.StringID(), err)
	}

	epDev, _, found := devices.Get(db.ReadTxn(), tables.DeviceIDIndex.Query(ep.GetIfIndex()))
	if !found {
		return fmt.Errorf("device %d not found for endpoint %s", ep.GetIfIndex(), ep.StringID())
	}

	return rm.UpsertRoute(routeReconciler.DesiredRoute{
		Owner:         owner,
		Prefix:        ip,
		Table:         routeReconciler.TableMain,
		AdminDistance: routeReconciler.AdminDistanceDefault,

		Device: epDev,
		Scope:  routeReconciler.SCOPE_LINK,
	})
}

func removeEndpointRoute(ep datapath.Endpoint, rm *routeReconciler.DesiredRouteManager) error {
	owner, err := rm.GetOwner("endpoint/" + ep.StringID())
	if err != nil {
		if errors.Is(err, routeReconciler.ErrOwnerDoesNotExist) {
			return nil
		}

		return fmt.Errorf("getting route owner for endpoint %s: %w", ep.StringID(), err)
	}

	return rm.RemoveOwner(owner)
}

func bpfMasqAddrs(ifName string, cfg *datapath.LocalNodeConfiguration) (masq4, masq6 netip.Addr) {
	if cfg.DeriveMasqIPAddrFromDevice != "" {
		ifName = cfg.DeriveMasqIPAddrFromDevice
	}

	find := func(devName string) bool {
		for _, addr := range cfg.NodeAddresses {
			if addr.DeviceName != devName {
				continue
			}
			if !addr.Primary {
				continue
			}
			if addr.Addr.Is4() && !masq4.IsValid() {
				masq4 = addr.Addr
			} else if addr.Addr.Is6() && !masq6.IsValid() {
				masq6 = addr.Addr
			}
			done := (!option.Config.EnableIPv4Masquerade || masq4.IsValid()) &&
				(!option.Config.EnableIPv6Masquerade || masq6.IsValid())
			if done {
				return true
			}
		}
		return false
	}

	// Try to find suitable masquerade address first from the given interface.
	if !find(ifName) {
		// No suitable masquerade addresses were found for this device. Try the fallback
		// addresses.
		find(tables.WildcardDeviceName)
	}

	return
}

// netdevRewrites prepares configuration data for attaching bpf_host.c to the
// specified externally-facing network device.
func netdevRewrites(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration, link netlink.Link) (*config.BPFHost, map[string]string) {
	cfg := config.NewBPFHost(config.NodeConfig(lnc))

	// External devices can be L2-less, in which case it won't have a MAC address
	// and its ethernet header length is set to 0.
	em := mac.MAC(link.Attrs().HardwareAddr)
	if len(em) == 6 {
		cfg.InterfaceMAC = em.As8()
	} else {
		cfg.EthHeaderLength = 0
	}

	cfg.SecurityLabel = ep.GetIdentity().Uint32()

	ifindex := link.Attrs().Index
	cfg.InterfaceIfIndex = uint32(ifindex)

	// Enable masquerading on external interfaces.
	if option.Config.EnableBPFMasquerade {
		ipv4, ipv6 := bpfMasqAddrs(link.Attrs().Name, lnc)

		if option.Config.EnableIPv4Masquerade && ipv4.IsValid() {
			cfg.NATIPv4Masquerade = ipv4.As4()
		}
		if option.Config.EnableIPv6Masquerade && ipv6.IsValid() {
			cfg.NATIPv6Masquerade = ipv6.As16()
		}
		// Masquerading IPv4 traffic from endpoints leaving the host.
		cfg.EnableRemoteNodeMasquerade = option.Config.EnableRemoteNodeMasquerade
	}

	cfg.EnableExtendedIPProtocols = option.Config.EnableExtendedIPProtocols
	cfg.HostEPID = uint16(lnc.HostEndpointID)
	cfg.EnableNoServiceEndpointsRoutable = lnc.SvcRouteConfig.EnableNoServiceEndpointsRoutable
	cfg.EnableNetkit = option.Config.DatapathMode == datapathOption.DatapathModeNetkit ||
		option.Config.DatapathMode == datapathOption.DatapathModeNetkitL2

	if lnc.EnableWireguard {
		cfg.WGIfIndex = lnc.WireguardIfIndex
		cfg.WGPort = wgtypes.ListenPort
	}

	if option.Config.EnableVTEP {
		cfg.VTEPMask = byteorder.NetIPv4ToHost32(net.IP(option.Config.VtepCidrMask))
	}

	if option.Config.EnableL2Announcements {
		cfg.EnableL2Announcements = true
		cfg.L2AnnouncementsMaxLiveness = uint64(option.Config.L2AnnouncerLeaseDuration.Nanoseconds())
	}

	cfg.AllowICMPFragNeeded = option.Config.AllowICMPFragNeeded
	cfg.EnableICMPRule = option.Config.EnableICMPRules

	cfg.EnableIPv4Fragments = option.Config.EnableIPv4 && option.Config.EnableIPv4FragmentsTracking
	cfg.EnableIPv6Fragments = option.Config.EnableIPv6 && option.Config.EnableIPv6FragmentsTracking

	renames := map[string]string{
		// Rename the calls map to include the device's ifindex.
		"cilium_calls": bpf.LocalMapName(callsmap.NetdevMapName, uint16(ifindex)),
		// Rename the policy map to include the host's endpoint id.
		"cilium_policy_v2": bpf.LocalMapName(policymap.MapName, uint16(ep.GetID())),
	}

	return cfg, renames
}

func isObsoleteDev(dev string, devices []string) bool {
	// exclude devices we never attach to/from_netdev to.
	for _, prefix := range defaults.ExcludedDevicePrefixes {
		if strings.HasPrefix(dev, prefix) {
			return false
		}
	}

	// exclude devices that will still be managed going forward.
	return !slices.Contains(devices, dev)
}

// removeObsoleteNetdevPrograms removes cil_to_netdev and cil_from_netdev from devices
// that cilium potentially doesn't manage anymore after a restart, e.g. if the set of
// devices changes between restarts.
//
// This code assumes that the agent was upgraded from a prior version while maintaining
// the same list of managed physical devices. This ensures that all tc bpf filters get
// replaced using the naming convention of the 'current' agent build. For example,
// before 1.13, most filters were named e.g. bpf_host.o:[to-host], to be changed to
// cilium-<device> in 1.13, then to cil_to_host-<device> in 1.14. As a result, this
// function only cleans up filters following the current naming scheme.
func removeObsoleteNetdevPrograms(logger *slog.Logger, devices []string) error {
	links, err := safenetlink.LinkList()
	if err != nil {
		return fmt.Errorf("retrieving all netlink devices: %w", err)
	}

	// collect all devices that have netdev programs attached on either ingress or egress.
	ingressDevs := []netlink.Link{}
	egressDevs := []netlink.Link{}
	for _, l := range links {
		if !isObsoleteDev(l.Attrs().Name, devices) {
			continue
		}

		// Remove the per-device bpffs directory containing pinned links and
		// per-endpoint maps.
		bpffsPath := bpffsDeviceDir(bpf.CiliumPath(), l)
		if err := bpf.Remove(bpffsPath); err != nil {
			logger.Error("Failed to remove bpffs entry",
				logfields.Error, err,
				logfields.BPFSPath, bpffsPath,
			)
		}

		ingressFilters, err := safenetlink.FilterList(l, directionToParent(dirIngress))
		if err != nil {
			return fmt.Errorf("listing ingress filters: %w", err)
		}
		for _, filter := range ingressFilters {
			if bpfFilter, ok := filter.(*netlink.BpfFilter); ok {
				if strings.HasPrefix(bpfFilter.Name, symbolFromHostNetdevEp) {
					ingressDevs = append(ingressDevs, l)
				}
			}
		}

		egressFilters, err := safenetlink.FilterList(l, directionToParent(dirEgress))
		if err != nil {
			return fmt.Errorf("listing egress filters: %w", err)
		}
		for _, filter := range egressFilters {
			if bpfFilter, ok := filter.(*netlink.BpfFilter); ok {
				if strings.HasPrefix(bpfFilter.Name, symbolToHostNetdevEp) {
					egressDevs = append(egressDevs, l)
				}
			}
		}
	}

	for _, dev := range ingressDevs {
		err = removeTCFilters(dev, directionToParent(dirIngress))
		if err != nil {
			logger.Error(
				"couldn't remove ingress tc filters",
				logfields.Error, err,
				logfields.Device, dev.Attrs().Name,
			)
		}
	}

	for _, dev := range egressDevs {
		err = removeTCFilters(dev, directionToParent(dirEgress))
		if err != nil {
			logger.Error(
				"couldn't remove egress tc filters",
				logfields.Error, err,
				logfields.Device, dev.Attrs().Name,
			)
		}
	}

	return nil
}

// reloadHostEndpoint (re)attaches programs from bpf_host.c to cilium_host,
// cilium_net and external (native) devices.
func reloadHostEndpoint(logger *slog.Logger, ep datapath.Endpoint, lnc *datapath.LocalNodeConfiguration, spec *ebpf.CollectionSpec) error {
	// Replace programs on cilium_host.
	if err := attachCiliumHost(logger, ep, lnc, spec); err != nil {
		return fmt.Errorf("attaching cilium_host: %w", err)
	}

	if err := attachCiliumNet(logger, ep, lnc, spec); err != nil {
		return fmt.Errorf("attaching cilium_host: %w", err)
	}

	if err := attachNetworkDevices(logger, ep, lnc, spec); err != nil {
		return fmt.Errorf("attaching cilium_host: %w", err)
	}

	return nil
}

// ciliumHostRewrites prepares configuration data for attaching bpf_host.c to
// the cilium_host network device.
func ciliumHostRewrites(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration) (*config.BPFHost, map[string]string) {
	cfg := config.NewBPFHost(config.NodeConfig(lnc))

	em := ep.GetNodeMAC()
	if len(em) != 6 {
		panic(fmt.Sprintf("invalid MAC address for cilium_host: %q", em))
	}
	cfg.InterfaceMAC = em.As8()

	cfg.InterfaceIfIndex = uint32(ep.GetIfIndex())

	cfg.SecurityLabel = ep.GetIdentity().Uint32()

	cfg.HostEPID = uint16(lnc.HostEndpointID)
	cfg.EnableNetkit = option.Config.DatapathMode == datapathOption.DatapathModeNetkit ||
		option.Config.DatapathMode == datapathOption.DatapathModeNetkitL2

	if lnc.EnableWireguard {
		cfg.WGIfIndex = lnc.WireguardIfIndex
		cfg.WGPort = wgtypes.ListenPort
	}

	if option.Config.EnableVTEP {
		cfg.VTEPMask = byteorder.NetIPv4ToHost32(net.IP(option.Config.VtepCidrMask))
	}

	if option.Config.EnableL2Announcements {
		cfg.EnableL2Announcements = true
		cfg.L2AnnouncementsMaxLiveness = uint64(option.Config.L2AnnouncerLeaseDuration.Nanoseconds())
	}

	cfg.AllowICMPFragNeeded = option.Config.AllowICMPFragNeeded
	cfg.EnableICMPRule = option.Config.EnableICMPRules

	cfg.EnableIPv4Fragments = option.Config.EnableIPv4 && option.Config.EnableIPv4FragmentsTracking
	cfg.EnableIPv6Fragments = option.Config.EnableIPv6 && option.Config.EnableIPv6FragmentsTracking

	renames := map[string]string{
		// Rename calls and policy maps to include the host endpoint's id.
		"cilium_calls":     bpf.LocalMapName(callsmap.HostMapName, uint16(ep.GetID())),
		"cilium_policy_v2": bpf.LocalMapName(policymap.MapName, uint16(ep.GetID())),
	}

	return cfg, renames
}

// attachCiliumHost inserts the host endpoint's policy program into the global
// cilium_call_policy map and attaches programs from bpf_host.c to cilium_host.
func attachCiliumHost(logger *slog.Logger, ep datapath.Endpoint, lnc *datapath.LocalNodeConfiguration, spec *ebpf.CollectionSpec) error {
	host, err := safenetlink.LinkByName(ep.InterfaceName())
	if err != nil {
		return fmt.Errorf("retrieving device %s: %w", ep.InterfaceName(), err)
	}

	co, renames := ciliumHostRewrites(ep, lnc)

	var hostObj hostObjects
	commit, err := bpf.LoadAndAssign(logger, &hostObj, spec, &bpf.CollectionOptions{
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
		},
		Constants:  co,
		MapRenames: renames,
	})
	if err != nil {
		return err
	}
	defer hostObj.Close()

	// Insert host endpoint policy program.
	if err := hostObj.PolicyMap.Update(uint32(ep.GetID()), hostObj.PolicyProg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("inserting host endpoint policy program: %w", err)
	}

	// Attach cil_to_host to cilium_host ingress.
	if err := attachSKBProgram(logger, host, hostObj.ToHost, symbolToHostEp,
		bpffsDeviceLinksDir(bpf.CiliumPath(), host), netlink.HANDLE_MIN_INGRESS, option.Config.EnableTCX); err != nil {
		return fmt.Errorf("interface %s ingress: %w", ep.InterfaceName(), err)
	}
	// Attach cil_from_host to cilium_host egress.
	if err := attachSKBProgram(logger, host, hostObj.FromHost, symbolFromHostEp,
		bpffsDeviceLinksDir(bpf.CiliumPath(), host), netlink.HANDLE_MIN_EGRESS, option.Config.EnableTCX); err != nil {
		return fmt.Errorf("interface %s egress: %w", ep.InterfaceName(), err)
	}

	if err := commit(); err != nil {
		return fmt.Errorf("committing bpf pins: %w", err)
	}

	return nil
}

// ciliumNetRewrites prepares configuration data for attaching bpf_host.c to
// the cilium_net network device.
func ciliumNetRewrites(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration, link netlink.Link) (*config.BPFHost, map[string]string) {
	cfg := config.NewBPFHost(config.NodeConfig(lnc))

	cfg.SecurityLabel = ep.GetIdentity().Uint32()

	em := mac.MAC(link.Attrs().HardwareAddr)
	if len(em) != 6 {
		panic(fmt.Sprintf("invalid MAC address for %s: %q", link.Attrs().Name, em))
	}
	cfg.InterfaceMAC = em.As8()

	cfg.EnableExtendedIPProtocols = option.Config.EnableExtendedIPProtocols
	cfg.EnableNoServiceEndpointsRoutable = lnc.SvcRouteConfig.EnableNoServiceEndpointsRoutable
	cfg.EnableNetkit = option.Config.DatapathMode == datapathOption.DatapathModeNetkit ||
		option.Config.DatapathMode == datapathOption.DatapathModeNetkitL2

	ifindex := link.Attrs().Index
	cfg.InterfaceIfIndex = uint32(ifindex)

	cfg.HostEPID = uint16(lnc.HostEndpointID)

	if lnc.EnableWireguard {
		cfg.WGIfIndex = lnc.WireguardIfIndex
		cfg.WGPort = wgtypes.ListenPort
	}

	if option.Config.EnableVTEP {
		cfg.VTEPMask = byteorder.NetIPv4ToHost32(net.IP(option.Config.VtepCidrMask))
	}

	cfg.AllowICMPFragNeeded = option.Config.AllowICMPFragNeeded
	cfg.EnableICMPRule = option.Config.EnableICMPRules

	cfg.EnableIPv4Fragments = option.Config.EnableIPv4 && option.Config.EnableIPv4FragmentsTracking
	cfg.EnableIPv6Fragments = option.Config.EnableIPv6 && option.Config.EnableIPv6FragmentsTracking

	renames := map[string]string{
		// Rename the calls map to include cilium_net's ifindex.
		"cilium_calls": bpf.LocalMapName(callsmap.NetdevMapName, uint16(ifindex)),
		// Rename the policy map to include the host endpoint's id.
		"cilium_policy_v2": bpf.LocalMapName(policymap.MapName, uint16(ep.GetID())),
	}

	return cfg, renames
}

// attachCiliumNet attaches programs from bpf_host.c to cilium_net.
func attachCiliumNet(logger *slog.Logger, ep datapath.Endpoint, lnc *datapath.LocalNodeConfiguration, spec *ebpf.CollectionSpec) error {
	net, err := safenetlink.LinkByName(defaults.SecondHostDevice)
	if err != nil {
		return fmt.Errorf("retrieving device %s: %w", defaults.SecondHostDevice, err)
	}

	co, renames := ciliumNetRewrites(ep, lnc, net)

	var netObj hostNetObjects
	commit, err := bpf.LoadAndAssign(logger, &netObj, spec, &bpf.CollectionOptions{
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
		},
		Constants:  co,
		MapRenames: renames,
	})
	if err != nil {
		return err
	}
	defer netObj.Close()

	// Attach cil_to_host to cilium_net.
	if err := attachSKBProgram(logger, net, netObj.ToHost, symbolToHostEp,
		bpffsDeviceLinksDir(bpf.CiliumPath(), net), netlink.HANDLE_MIN_INGRESS, option.Config.EnableTCX); err != nil {
		return fmt.Errorf("interface %s ingress: %w", defaults.SecondHostDevice, err)
	}

	if err := commit(); err != nil {
		return fmt.Errorf("committing bpf pins: %w", err)
	}

	return nil
}

// attachNetworkDevices attaches programs from bpf_host.c to externally-facing
// devices and the wireguard device. Attaches cil_from_netdev to ingress and
// optionally cil_to_netdev to egress if enabled features require it.
func attachNetworkDevices(logger *slog.Logger, ep datapath.Endpoint, lnc *datapath.LocalNodeConfiguration, spec *ebpf.CollectionSpec) error {
	devices := lnc.DeviceNames()

	// Selectively attach bpf_host to cilium_ipip{4,6} in order to have a
	// service lookup after IPIP termination. Do not attach in case of the
	// devices being created via health datapath (see Reinitialize()) since
	// it can push packets up the local stack which should be handled by
	// the host instead.
	if option.Config.EnableIPIPTermination && !option.Config.EnableHealthDatapath {
		if option.Config.IPv4Enabled() {
			devices = append(devices, defaults.IPIPv4Device)
		}
		if option.Config.IPv6Enabled() {
			devices = append(devices, defaults.IPIPv6Device)
		}
	}

	// Replace programs on physical devices, ignoring devices that don't exist.
	for _, device := range devices {
		iface, err := safenetlink.LinkByName(device)
		if err != nil {
			logger.Warn(
				"Link does not exist",
				logfields.Error, err,
				logfields.Device, device,
			)
			continue
		}

		linkDir := bpffsDeviceLinksDir(bpf.CiliumPath(), iface)

		co, renames := netdevRewrites(ep, lnc, iface)

		var netdevObj hostNetdevObjects
		commit, err := bpf.LoadAndAssign(logger, &netdevObj, spec, &bpf.CollectionOptions{
			CollectionOptions: ebpf.CollectionOptions{
				Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
			},
			Constants:  co,
			MapRenames: renames,
		})
		if err != nil {
			return err
		}
		defer netdevObj.Close()

		// Attach cil_from_netdev to ingress.
		if err := attachSKBProgram(logger, iface, netdevObj.FromNetdev, symbolFromHostNetdevEp,
			linkDir, netlink.HANDLE_MIN_INGRESS, option.Config.EnableTCX); err != nil {
			return fmt.Errorf("interface %s ingress: %w", device, err)
		}

		if option.Config.AreDevicesRequired(lnc.KPRConfig, lnc.EnableWireguard, lnc.EnableIPSec) {
			// Attach cil_to_netdev to egress.
			if err := attachSKBProgram(logger, iface, netdevObj.ToNetdev, symbolToHostNetdevEp,
				linkDir, netlink.HANDLE_MIN_EGRESS, option.Config.EnableTCX); err != nil {
				return fmt.Errorf("interface %s egress: %w", device, err)
			}
		} else {
			// Remove any previously attached device from egress path if BPF
			// NodePort and host firewall are disabled.
			if err := detachSKBProgram(logger, iface, symbolToHostNetdevEp, linkDir, netlink.HANDLE_MIN_EGRESS); err != nil {
				logger.Error(
					"",
					logfields.Error, err,
					logfields.Device, device,
				)
			}
		}

		if err := commit(); err != nil {
			return fmt.Errorf("committing bpf pins: %w", err)
		}
	}

	// Call immediately after attaching programs to make it obvious that a
	// program was wrongfully detached due to a bug or misconfiguration.
	if err := removeObsoleteNetdevPrograms(logger, devices); err != nil {
		logger.Error("Failed to remove obsolete netdev programs", logfields.Error, err)
	}

	return nil
}

// endpointRewrites prepares configuration data for attaching bpf_lxc.c to the
// specified workload endpoint.
func endpointRewrites(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration) (*config.BPFLXC, map[string]string) {
	cfg := config.NewBPFLXC(config.NodeConfig(lnc))

	if ep.IPv4Address().IsValid() {
		cfg.EndpointIPv4 = ep.IPv4Address().As4()
	}
	if ep.IPv6Address().IsValid() {
		cfg.EndpointIPv6 = ep.IPv6Address().As16()
	}

	// Netkit devices can be L2-less, meaning they operate with a zero MAC
	// address. Unlike other L2-less devices, the ethernet header length remains
	// at its default non-zero value.
	em := ep.GetNodeMAC()
	if len(em) == 6 {
		cfg.InterfaceMAC = em.As8()
	}

	cfg.InterfaceIfIndex = uint32(ep.GetIfIndex())

	cfg.EndpointID = uint16(ep.GetID())
	cfg.EndpointNetNSCookie = ep.GetEndpointNetNsCookie()

	cfg.SecurityLabel = ep.GetIdentity().Uint32()

	cfg.PolicyVerdictLogFilter = ep.GetPolicyVerdictLogFilter()

	cfg.HostEPID = uint16(lnc.HostEndpointID)
	cfg.EnableNoServiceEndpointsRoutable = lnc.SvcRouteConfig.EnableNoServiceEndpointsRoutable
	cfg.EnableExtendedIPProtocols = option.Config.EnableExtendedIPProtocols
	cfg.EnableNetkit = option.Config.DatapathMode == datapathOption.DatapathModeNetkit ||
		option.Config.DatapathMode == datapathOption.DatapathModeNetkitL2

	if option.Config.EnableVTEP {
		cfg.VTEPMask = byteorder.NetIPv4ToHost32(net.IP(option.Config.VtepCidrMask))
	}

	cfg.AllowICMPFragNeeded = option.Config.AllowICMPFragNeeded
	cfg.EnableICMPRule = option.Config.EnableICMPRules
	cfg.EnableLRP = option.Config.EnableLocalRedirectPolicy

	cfg.EnableIPv4Fragments = option.Config.EnableIPv4 && option.Config.EnableIPv4FragmentsTracking
	cfg.EnableIPv6Fragments = option.Config.EnableIPv6 && option.Config.EnableIPv6FragmentsTracking

	renames := map[string]string{
		// Rename the calls and policy maps to include the endpoint's id.
		"cilium_calls":     bpf.LocalMapName(callsmap.MapName, uint16(ep.GetID())),
		"cilium_policy_v2": bpf.LocalMapName(policymap.MapName, uint16(ep.GetID())),
	}

	return cfg, renames
}

// reloadEndpoint loads programs in spec into the device used by ep.
//
// spec is modified by the method and it is the callers responsibility to copy
// it if necessary.
func reloadEndpoint(logger *slog.Logger, db *statedb.DB, devices statedb.Table[*tables.Device], rm *routeReconciler.DesiredRouteManager, ep datapath.Endpoint, lnc *datapath.LocalNodeConfiguration, spec *ebpf.CollectionSpec) error {
	device := ep.InterfaceName()

	co, renames := endpointRewrites(ep, lnc)

	var obj lxcObjects
	commit, err := bpf.LoadAndAssign(logger, &obj, spec, &bpf.CollectionOptions{
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
		},
		Constants:  co,
		MapRenames: renames,
	})
	if err != nil {
		return err
	}
	defer obj.Close()

	// Insert policy programs before attaching entrypoints to tc hooks.
	// Inserting a policy program is considered an attachment, since it makes
	// the code reachable by bpf_host when it evaluates policy for the endpoint.
	// All internal tail call plumbing needs to be done before this point.
	// If the agent dies uncleanly after the first program has been inserted,
	// the endpoint's connectivity will be partially broken or exhibit undefined
	// behaviour like missed tail calls or drops.
	if err := obj.PolicyMap.Update(uint32(ep.GetID()), obj.PolicyProg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("inserting endpoint policy program: %w", err)
	}
	if err := obj.EgressPolicyMap.Update(uint32(ep.GetID()), obj.EgressPolicyProg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("inserting endpoint egress policy program: %w", err)
	}

	iface, err := safenetlink.LinkByName(device)
	if err != nil {
		return fmt.Errorf("retrieving device %s: %w", device, err)
	}

	linkDir := bpffsEndpointLinksDir(bpf.CiliumPath(), ep)
	if err := attachSKBProgram(logger, iface, obj.FromContainer, symbolFromEndpoint,
		linkDir, netlink.HANDLE_MIN_INGRESS, option.Config.EnableTCX); err != nil {
		return fmt.Errorf("interface %s ingress: %w", device, err)
	}

	if ep.RequireEgressProg() {
		if err := attachSKBProgram(logger, iface, obj.ToContainer, symbolToEndpoint,
			linkDir, netlink.HANDLE_MIN_EGRESS, option.Config.EnableTCX); err != nil {
			return fmt.Errorf("interface %s egress: %w", device, err)
		}
	} else {
		if err := detachSKBProgram(logger, iface, symbolToEndpoint, linkDir, netlink.HANDLE_MIN_EGRESS); err != nil {
			logger.Error(
				"",
				logfields.Error, err,
				logfields.Device, device,
			)
		}
	}

	if err := commit(); err != nil {
		return fmt.Errorf("committing bpf pins: %w", err)
	}

	if ep.RequireEndpointRoute() {
		scopedLog := ep.Logger(subsystem).With(
			logfields.Interface, device,
		)
		if ip := ep.IPv4Address(); ip.IsValid() {
			if err := upsertEndpointRoute(logger, db, devices, rm, ep, netip.PrefixFrom(ip, ip.BitLen())); err != nil {
				scopedLog.Warn("Failed to upsert route",
					logfields.Error, err,
				)
			}
		}
		if ip := ep.IPv6Address(); ip.IsValid() {
			if err := upsertEndpointRoute(logger, db, devices, rm, ep, netip.PrefixFrom(ip, ip.BitLen())); err != nil {
				scopedLog.Warn("Failed to upsert route",
					logfields.Error, err,
				)
			}
		}
	}

	return nil
}

func replaceOverlayDatapath(ctx context.Context, logger *slog.Logger, lnc *datapath.LocalNodeConfiguration, cArgs []string, device netlink.Link) error {
	if err := compileOverlay(ctx, logger, cArgs); err != nil {
		return fmt.Errorf("compiling overlay program: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(overlayObj)
	if err != nil {
		return fmt.Errorf("loading eBPF ELF %s: %w", overlayObj, err)
	}

	cfg := config.NewBPFOverlay(config.NodeConfig(lnc))
	cfg.InterfaceIfIndex = uint32(device.Attrs().Index)

	cfg.EnableExtendedIPProtocols = option.Config.EnableExtendedIPProtocols
	cfg.EnableNoServiceEndpointsRoutable = lnc.SvcRouteConfig.EnableNoServiceEndpointsRoutable
	cfg.EnableNetkit = option.Config.DatapathMode == datapathOption.DatapathModeNetkit ||
		option.Config.DatapathMode == datapathOption.DatapathModeNetkitL2

	if option.Config.EnableVTEP {
		cfg.VTEPMask = byteorder.NetIPv4ToHost32(net.IP(option.Config.VtepCidrMask))
	}

	cfg.EnableIPv4Fragments = option.Config.EnableIPv4 && option.Config.EnableIPv4FragmentsTracking
	cfg.EnableIPv6Fragments = option.Config.EnableIPv6 && option.Config.EnableIPv6FragmentsTracking

	var obj overlayObjects
	commit, err := bpf.LoadAndAssign(logger, &obj, spec, &bpf.CollectionOptions{
		Constants: cfg,
		MapRenames: map[string]string{
			"cilium_calls": fmt.Sprintf("cilium_calls_overlay_%d", identity.ReservedIdentityWorld),
		},
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
		},
	})
	if err != nil {
		return err
	}
	defer obj.Close()

	linkDir := bpffsDeviceLinksDir(bpf.CiliumPath(), device)
	if err := attachSKBProgram(logger, device, obj.FromOverlay, symbolFromOverlay,
		linkDir, netlink.HANDLE_MIN_INGRESS, option.Config.EnableTCX); err != nil {
		return fmt.Errorf("interface %s ingress: %w", device, err)
	}
	if err := attachSKBProgram(logger, device, obj.ToOverlay, symbolToOverlay,
		linkDir, netlink.HANDLE_MIN_EGRESS, option.Config.EnableTCX); err != nil {
		return fmt.Errorf("interface %s egress: %w", device, err)
	}

	if err := commit(); err != nil {
		return fmt.Errorf("committing bpf pins: %w", err)
	}

	return nil
}

func replaceWireguardDatapath(ctx context.Context, logger *slog.Logger, lnc *datapath.LocalNodeConfiguration, device netlink.Link) (err error) {
	if err := compileWireguard(ctx, logger); err != nil {
		return fmt.Errorf("compiling wireguard program: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(wireguardObj)
	if err != nil {
		return fmt.Errorf("loading eBPF ELF %s: %w", wireguardObj, err)
	}

	cfg := config.NewBPFWireguard(config.NodeConfig(lnc))
	cfg.InterfaceIfIndex = uint32(device.Attrs().Index)

	cfg.EnableExtendedIPProtocols = option.Config.EnableExtendedIPProtocols
	cfg.EnableNetkit = option.Config.DatapathMode == datapathOption.DatapathModeNetkit ||
		option.Config.DatapathMode == datapathOption.DatapathModeNetkitL2

	var obj wireguardObjects
	commit, err := bpf.LoadAndAssign(logger, &obj, spec, &bpf.CollectionOptions{
		Constants: cfg,
		MapRenames: map[string]string{
			"cilium_calls": fmt.Sprintf("cilium_calls_wireguard_%d", device.Attrs().Index),
		},
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
		},
	})
	if err != nil {
		return err
	}
	defer obj.Close()

	linkDir := bpffsDeviceLinksDir(bpf.CiliumPath(), device)
	// Attach/detach cil_to_wireguard to/from egress.
	if option.Config.NeedEgressOnWireGuardDevice(lnc.KPRConfig, lnc.EnableWireguard) {
		if err := attachSKBProgram(logger, device, obj.ToWireguard, symbolToWireguard,
			linkDir, netlink.HANDLE_MIN_EGRESS, option.Config.EnableTCX); err != nil {
			return fmt.Errorf("interface %s egress: %w", device, err)
		}
	} else {
		if err := detachSKBProgram(logger, device, symbolToWireguard,
			linkDir, netlink.HANDLE_MIN_EGRESS); err != nil {
			logger.Error("",
				logfields.Error, err,
				logfields.Device, device,
			)
		}
	}
	// Attach/detach cil_from_wireguard to/from ingress.
	if option.Config.NeedIngressOnWireGuardDevice(lnc.KPRConfig, lnc.EnableWireguard) {
		if err := attachSKBProgram(logger, device, obj.FromWireguard, symbolFromWireguard,
			linkDir, netlink.HANDLE_MIN_INGRESS, option.Config.EnableTCX); err != nil {
			return fmt.Errorf("interface %s ingress: %w", device, err)
		}
	} else {
		if err := detachSKBProgram(logger, device, symbolFromWireguard,
			linkDir, netlink.HANDLE_MIN_INGRESS); err != nil {
			logger.Error("",
				logfields.Error, err,
				logfields.Device, device,
			)
		}
	}
	if err := commit(); err != nil {
		return fmt.Errorf("committing bpf pins: %w", err)
	}
	return nil
}

// ReloadDatapath reloads the BPF datapath programs for the specified endpoint.
//
// It attempts to find a pre-compiled
// template datapath object to use, to avoid a costly compile operation.
// Only if there is no existing template that has the same configuration
// parameters as the specified endpoint, this function will compile a new
// template for this configuration.
//
// This function will block if the cache does not contain an entry for the
// same EndpointConfiguration and multiple goroutines attempt to concurrently
// CompileOrLoad with the same configuration parameters. When the first
// goroutine completes compilation of the template, all other CompileOrLoad
// invocations will be released.
func (l *loader) ReloadDatapath(ctx context.Context, ep datapath.Endpoint, lnc *datapath.LocalNodeConfiguration, stats *metrics.SpanStat) (string, error) {
	dirs := directoryInfo{
		Library: option.Config.BpfDir,
		Runtime: option.Config.StateDir,
		State:   ep.StateDir(),
		Output:  ep.StateDir(),
	}

	spec, hash, err := l.templateCache.fetchOrCompile(ctx, lnc, ep, &dirs, stats)
	if err != nil {
		return "", err
	}

	if ep.IsHost() {
		// Reload bpf programs on cilium_host and cilium_net.
		stats.BpfLoadProg.Start()
		err = reloadHostEndpoint(l.logger, ep, lnc, spec)
		stats.BpfLoadProg.End(err == nil)

		l.hostDpInitializedOnce.Do(func() {
			l.logger.Debug("Initialized host datapath")
			close(l.hostDpInitialized)
		})

		return hash, err
	}

	// Reload an lxc endpoint program.
	stats.BpfLoadProg.Start()
	err = reloadEndpoint(l.logger, l.db, l.devices, l.routeManager, ep, lnc, spec)
	stats.BpfLoadProg.End(err == nil)
	return hash, err
}

// Unload removes the datapath specific program aspects
func (l *loader) Unload(ep datapath.Endpoint) {
	if ep.RequireEndpointRoute() {
		if ip := ep.IPv4Address(); ip.IsValid() {
			removeEndpointRoute(ep, l.routeManager)
		}

		if ip := ep.IPv6Address(); ip.IsValid() {
			removeEndpointRoute(ep, l.routeManager)
		}
	}

	log := l.logger.With(logfields.EndpointID, ep.StringID())

	// Remove legacy tc attachments.
	link, err := safenetlink.LinkByName(ep.InterfaceName())
	if err == nil {
		if err := removeTCFilters(link, netlink.HANDLE_MIN_INGRESS); err != nil {
			log.Error(
				"Failed to remove ingress filter from interface",
				logfields.Error, err,
				logfields.Interface, ep.InterfaceName(),
			)
		}
		if err := removeTCFilters(link, netlink.HANDLE_MIN_EGRESS); err != nil {
			log.Error(
				"Failed to remove egress filter from interface",
				logfields.Error, err,
				logfields.Interface, ep.InterfaceName(),
			)
		}
	}

	// If Cilium and the kernel support tcx to attach TC programs to the
	// endpoint's veth device, its bpf_link object is pinned to a per-endpoint
	// bpffs directory. When the endpoint gets deleted, we can remove the whole
	// directory to clean up any leftover pinned links and maps.

	// Remove the links directory first to avoid removing program arrays before
	// the entrypoints are detached.
	if err := bpf.Remove(bpffsEndpointLinksDir(bpf.CiliumPath(), ep)); err != nil {
		log.Error("Failed to remove bpffs entry",
			logfields.Error, err,
			logfields.BPFFSEndpointLinksDir, bpffsEndpointLinksDir(bpf.CiliumPath(), ep),
		)
	}
	// Finally, remove the endpoint's top-level directory.
	if err := bpf.Remove(bpffsEndpointDir(bpf.CiliumPath(), ep)); err != nil {
		log.Error("Failed to remove bpffs entry",
			logfields.Error, err,
			logfields.BPFFSEndpointDir, bpffsEndpointDir(bpf.CiliumPath(), ep),
		)
	}
}

// EndpointHash hashes the specified endpoint configuration with the current
// datapath hash cache and returns the hash as string.
func (l *loader) EndpointHash(cfg datapath.EndpointConfiguration, lnCfg *datapath.LocalNodeConfiguration) (string, error) {
	return l.templateCache.baseHash.hashEndpoint(l.templateCache, lnCfg, cfg)
}

// CallsMapPath gets the BPF Calls Map for the endpoint with the specified ID.
func (l *loader) CallsMapPath(id uint16) string {
	return bpf.LocalMapPath(l.logger, callsmap.MapName, id)
}

// HostDatapathInitialized returns a channel which is closed when the
// host datapath has been loaded for the first time.
func (l *loader) HostDatapathInitialized() <-chan struct{} {
	return l.hostDpInitialized
}

func (l *loader) WriteEndpointConfig(w io.Writer, e datapath.EndpointConfiguration, lnCfg *datapath.LocalNodeConfiguration) error {
	return l.configWriter.WriteEndpointConfig(w, lnCfg, e)
}
