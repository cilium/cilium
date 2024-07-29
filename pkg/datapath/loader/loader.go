// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/callsmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
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

	symbolToWireguard = "cil_to_wireguard"

	symbolFromHostNetdevXDP = "cil_xdp_entry"

	symbolFromOverlay = "cil_from_overlay"
	symbolToOverlay   = "cil_to_overlay"

	dirIngress = "ingress"
	dirEgress  = "egress"
)

const (
	secctxFromIpcacheDisabled = iota + 1
	secctxFromIpcacheEnabled
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsystem)

// loader is a wrapper structure around operations related to compiling,
// loading, and reloading datapath programs.
type loader struct {
	cfg Config

	nodeConfig atomic.Pointer[datapath.LocalNodeConfiguration]

	// templateCache is the cache of pre-compiled datapaths. Only set after
	// a call to Reinitialize.
	templateCache *objectCache

	ipsecMu lock.Mutex // guards reinitializeIPSec

	hostDpInitializedOnce sync.Once
	hostDpInitialized     chan struct{}

	sysctl          sysctl.Sysctl
	prefilter       datapath.PreFilter
	compilationLock datapath.CompilationLock
	configWriter    datapath.ConfigWriter
	nodeHandler     datapath.NodeHandler
}

type Params struct {
	cell.In

	Config          Config
	Sysctl          sysctl.Sysctl
	Prefilter       datapath.PreFilter
	CompilationLock datapath.CompilationLock
	ConfigWriter    datapath.ConfigWriter
	NodeHandler     datapath.NodeHandler
}

// newLoader returns a new loader.
func newLoader(p Params) *loader {
	return &loader{
		cfg:               p.Config,
		templateCache:     newObjectCache(p.ConfigWriter, filepath.Join(option.Config.StateDir, defaults.TemplatesDir)),
		sysctl:            p.Sysctl,
		hostDpInitialized: make(chan struct{}),
		prefilter:         p.Prefilter,
		compilationLock:   p.CompilationLock,
		configWriter:      p.ConfigWriter,
		nodeHandler:       p.NodeHandler,
	}
}

func upsertEndpointRoute(ep datapath.Endpoint, ip net.IPNet) error {
	endpointRoute := route.Route{
		Prefix: ip,
		Device: ep.InterfaceName(),
		Scope:  netlink.SCOPE_LINK,
		Proto:  linux_defaults.RTProto,
	}

	return route.Upsert(endpointRoute)
}

func removeEndpointRoute(ep datapath.Endpoint, ip net.IPNet) error {
	return route.Delete(route.Route{
		Prefix: ip,
		Device: ep.InterfaceName(),
		Scope:  netlink.SCOPE_LINK,
	})
}

func (l *loader) bpfMasqAddrs(ifName string) (masq4, masq6 netip.Addr) {
	if l.cfg.DeriveMasqIPAddrFromDevice != "" {
		ifName = l.cfg.DeriveMasqIPAddrFromDevice
	}

	addrs := l.nodeConfig.Load().NodeAddresses

	find := func(devName string) bool {
		for _, addr := range addrs {
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

// patchHostNetdevDatapath calculates the changes necessary
// to attach the host endpoint datapath to different interfaces.
func (l *loader) patchHostNetdevDatapath(ep datapath.Endpoint, ifName string) (map[string]uint64, map[string]string, error) {
	opts := ELFVariableSubstitutions(ep)
	strings := ELFMapSubstitutions(ep)

	iface, err := netlink.LinkByName(ifName)
	if err != nil {
		return nil, nil, err
	}

	// The THIS_INTERFACE_MAC value is specific to each attachment interface.
	mac := mac.MAC(iface.Attrs().HardwareAddr)
	if mac == nil {
		// L2-less device
		mac = make([]byte, 6)
		opts["ETH_HLEN"] = uint64(0)
	}
	opts["THIS_INTERFACE_MAC_1"] = uint64(sliceToBe32(mac[0:4]))
	opts["THIS_INTERFACE_MAC_2"] = uint64(sliceToBe16(mac[4:6]))

	ifIndex := uint32(iface.Attrs().Index)

	if !option.Config.EnableHostLegacyRouting {
		opts["SECCTX_FROM_IPCACHE"] = uint64(secctxFromIpcacheEnabled)
	} else {
		opts["SECCTX_FROM_IPCACHE"] = uint64(secctxFromIpcacheDisabled)
	}

	opts["NATIVE_DEV_IFINDEX"] = uint64(ifIndex)

	if option.Config.EnableBPFMasquerade && ifName != defaults.SecondHostDevice {
		ipv4, ipv6 := l.bpfMasqAddrs(ifName)

		if option.Config.EnableIPv4Masquerade && ipv4.IsValid() {
			opts["IPV4_MASQUERADE"] = uint64(byteorder.NetIPv4ToHost32(ipv4.AsSlice()))
		}
		if option.Config.EnableIPv6Masquerade && ipv6.IsValid() {
			ipv6Bytes := ipv6.AsSlice()
			opts["IPV6_MASQUERADE_1"] = sliceToBe64(ipv6Bytes[0:8])
			opts["IPV6_MASQUERADE_2"] = sliceToBe64(ipv6Bytes[8:16])
		}
	}

	callsMapHostDevice := bpf.LocalMapName(callsmap.HostMapName, templateLxcID)
	strings[callsMapHostDevice] = bpf.LocalMapName(callsmap.NetdevMapName, uint16(ifIndex))

	return opts, strings, nil
}

func isObsoleteDev(dev string, devices []string) bool {
	// exclude devices we never attach to/from_netdev to.
	for _, prefix := range defaults.ExcludedDevicePrefixes {
		if strings.HasPrefix(dev, prefix) {
			return false
		}
	}

	// exclude devices that will still be managed going forward.
	for _, d := range devices {
		if dev == d {
			return false
		}
	}

	return true
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
func removeObsoleteNetdevPrograms(devices []string) error {
	links, err := netlink.LinkList()
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
			log.WithError(err).WithField(logfields.Device, l.Attrs().Name)
		}

		ingressFilters, err := netlink.FilterList(l, directionToParent(dirIngress))
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

		egressFilters, err := netlink.FilterList(l, directionToParent(dirEgress))
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
			log.WithError(err).Errorf("couldn't remove ingress tc filters from %s", dev.Attrs().Name)
		}
	}

	for _, dev := range egressDevs {
		err = removeTCFilters(dev, directionToParent(dirEgress))
		if err != nil {
			log.WithError(err).Errorf("couldn't remove egress tc filters from %s", dev.Attrs().Name)
		}
	}

	return nil
}

// reloadHostDatapath (re)attaches programs from bpf_host.c to:
// - cilium_host: cil_to_host ingress and cil_from_host to egress
// - cilium_net: cil_to_host to ingress
// - native devices: cil_from_netdev to ingress and (optionally) cil_to_netdev to egress if certain features require it
func (l *loader) reloadHostDatapath(ep datapath.Endpoint, spec *ebpf.CollectionSpec, devices []string) error {
	// Replace programs on cilium_host.
	host, err := netlink.LinkByName(ep.InterfaceName())
	if err != nil {
		return fmt.Errorf("retrieving device %s: %w", ep.InterfaceName(), err)
	}

	coll, commit, err := loadDatapath(spec, ELFMapSubstitutions(ep), ELFVariableSubstitutions(ep))
	if err != nil {
		return err
	}
	defer coll.Close()

	// Attach cil_to_host to cilium_host ingress.
	if err := attachSKBProgram(host, coll.Programs[symbolToHostEp], symbolToHostEp,
		bpffsDeviceLinksDir(bpf.CiliumPath(), host), netlink.HANDLE_MIN_INGRESS, option.Config.EnableTCX); err != nil {
		return fmt.Errorf("interface %s ingress: %w", ep.InterfaceName(), err)
	}
	// Attach cil_from_host to cilium_host egress.
	if err := attachSKBProgram(host, coll.Programs[symbolFromHostEp], symbolFromHostEp,
		bpffsDeviceLinksDir(bpf.CiliumPath(), host), netlink.HANDLE_MIN_EGRESS, option.Config.EnableTCX); err != nil {
		return fmt.Errorf("interface %s egress: %w", ep.InterfaceName(), err)
	}

	if err := commit(); err != nil {
		return fmt.Errorf("committing bpf pins: %w", err)
	}

	// Replace program on cilium_net.
	net, err := netlink.LinkByName(defaults.SecondHostDevice)
	if err != nil {
		return fmt.Errorf("retrieving device %s: %w", defaults.SecondHostDevice, err)
	}

	secondConsts, secondRenames, err := l.patchHostNetdevDatapath(ep, defaults.SecondHostDevice)
	if err != nil {
		return err
	}

	coll, commit, err = loadDatapath(spec, secondRenames, secondConsts)
	if err != nil {
		return err
	}
	defer coll.Close()

	// Attach cil_to_host to cilium_net.
	if err := attachSKBProgram(net, coll.Programs[symbolToHostEp], symbolToHostEp,
		bpffsDeviceLinksDir(bpf.CiliumPath(), net), netlink.HANDLE_MIN_INGRESS, option.Config.EnableTCX); err != nil {
		return fmt.Errorf("interface %s ingress: %w", defaults.SecondHostDevice, err)
	}

	if err := commit(); err != nil {
		return fmt.Errorf("committing bpf pins: %w", err)
	}

	// Replace programs on physical devices, ignoring devices that don't exist.
	for _, device := range devices {
		iface, err := netlink.LinkByName(device)
		if err != nil {
			log.WithError(err).WithField("device", device).Warn("Link does not exist")
			continue
		}

		linkDir := bpffsDeviceLinksDir(bpf.CiliumPath(), iface)

		netdevConsts, netdevRenames, err := l.patchHostNetdevDatapath(ep, device)
		if err != nil {
			return err
		}

		coll, commit, err := loadDatapath(spec, netdevRenames, netdevConsts)
		if err != nil {
			return err
		}
		defer coll.Close()

		// Attach cil_from_netdev to ingress.
		if err := attachSKBProgram(iface, coll.Programs[symbolFromHostNetdevEp], symbolFromHostNetdevEp,
			linkDir, netlink.HANDLE_MIN_INGRESS, option.Config.EnableTCX); err != nil {
			return fmt.Errorf("interface %s ingress: %w", device, err)
		}

		if option.Config.AreDevicesRequired() {
			// Attaching bpf_host to cilium_wg0 is required for encrypting KPR
			// traffic. Only ingress prog (aka "from-netdev") is needed to handle
			// the rev-NAT xlations.
			if device != wgTypes.IfaceName {
				// Attach cil_to_netdev to egress.
				if err := attachSKBProgram(iface, coll.Programs[symbolToHostNetdevEp], symbolToHostNetdevEp,
					linkDir, netlink.HANDLE_MIN_EGRESS, option.Config.EnableTCX); err != nil {
					return fmt.Errorf("interface %s egress: %w", device, err)
				}
			}
		} else {
			// Remove any previously attached device from egress path if BPF
			// NodePort and host firewall are disabled.
			if err := detachSKBProgram(iface, symbolToHostNetdevEp, linkDir, netlink.HANDLE_MIN_EGRESS); err != nil {
				log.WithField("device", device).Error(err)
			}
		}

		if err := commit(); err != nil {
			return fmt.Errorf("committing bpf pins: %w", err)
		}
	}

	// call at the end of the function so that we can easily detect if this removes necessary
	// programs that have just been attached.
	if err := removeObsoleteNetdevPrograms(devices); err != nil {
		log.WithError(err).Error("Failed to remove obsolete netdev programs")
	}

	l.hostDpInitializedOnce.Do(func() {
		log.Debug("Initialized host datapath")
		close(l.hostDpInitialized)
	})

	return nil
}

// reloadDatapath loads programs in spec into the device used by ep.
//
// spec is modified by the method and it is the callers responsibility to copy
// it if necessary.
func (l *loader) reloadDatapath(ep datapath.Endpoint, spec *ebpf.CollectionSpec) error {
	device := ep.InterfaceName()

	// Replace all occurrences of the template endpoint ID with the real ID.
	for _, name := range []string{
		policymap.PolicyCallMapName,
		policymap.PolicyEgressCallMapName,
	} {
		pm, ok := spec.Maps[name]
		if !ok {
			continue
		}

		for i, kv := range pm.Contents {
			if kv.Key == (uint32)(templateLxcID) {
				pm.Contents[i].Key = (uint32)(ep.GetID())
			}
		}
	}

	if ep.IsHost() {
		devices := l.nodeConfig.Load().DeviceNames()

		if option.Config.NeedBPFHostOnWireGuardDevice() {
			devices = append(devices, wgTypes.IfaceName)
		}

		if err := l.reloadHostDatapath(ep, spec, devices); err != nil {
			return err
		}
	} else {
		coll, commit, err := loadDatapath(spec, ELFMapSubstitutions(ep), ELFVariableSubstitutions(ep))
		if err != nil {
			return err
		}
		defer coll.Close()

		iface, err := netlink.LinkByName(device)
		if err != nil {
			return fmt.Errorf("retrieving device %s: %w", device, err)
		}

		linkDir := bpffsEndpointLinksDir(bpf.CiliumPath(), ep)
		if err := attachSKBProgram(iface, coll.Programs[symbolFromEndpoint], symbolFromEndpoint,
			linkDir, netlink.HANDLE_MIN_INGRESS, option.Config.EnableTCX); err != nil {
			return fmt.Errorf("interface %s ingress: %w", device, err)
		}

		if ep.RequireEgressProg() {
			if err := attachSKBProgram(iface, coll.Programs[symbolToEndpoint], symbolToEndpoint,
				linkDir, netlink.HANDLE_MIN_EGRESS, option.Config.EnableTCX); err != nil {
				return fmt.Errorf("interface %s egress: %w", device, err)
			}
		} else {
			if err := detachSKBProgram(iface, symbolToEndpoint, linkDir, netlink.HANDLE_MIN_EGRESS); err != nil {
				log.WithField("device", device).Error(err)
			}
		}

		if err := commit(); err != nil {
			return fmt.Errorf("committing bpf pins: %w", err)
		}
	}

	if ep.RequireEndpointRoute() {
		scopedLog := ep.Logger(subsystem).WithFields(logrus.Fields{
			logfields.Interface: device,
		})
		if ip := ep.IPv4Address(); ip.IsValid() {
			if err := upsertEndpointRoute(ep, *iputil.AddrToIPNet(ip)); err != nil {
				scopedLog.WithError(err).Warn("Failed to upsert route")
			}
		}
		if ip := ep.IPv6Address(); ip.IsValid() {
			if err := upsertEndpointRoute(ep, *iputil.AddrToIPNet(ip)); err != nil {
				scopedLog.WithError(err).Warn("Failed to upsert route")
			}
		}
	}

	return nil
}

func (l *loader) replaceOverlayDatapath(ctx context.Context, cArgs []string, iface string) error {
	if err := compileOverlay(ctx, cArgs); err != nil {
		return fmt.Errorf("compiling overlay program: %w", err)
	}

	device, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("retrieving device %s: %w", iface, err)
	}

	spec, err := bpf.LoadCollectionSpec(overlayObj)
	if err != nil {
		return fmt.Errorf("loading eBPF ELF %s: %w", overlayObj, err)
	}

	coll, commit, err := loadDatapath(spec, nil, nil)
	if err != nil {
		return err
	}
	defer coll.Close()

	linkDir := bpffsDeviceLinksDir(bpf.CiliumPath(), device)
	if err := attachSKBProgram(device, coll.Programs[symbolFromOverlay], symbolFromOverlay,
		linkDir, netlink.HANDLE_MIN_INGRESS, option.Config.EnableTCX); err != nil {
		return fmt.Errorf("interface %s ingress: %w", device, err)
	}
	if err := attachSKBProgram(device, coll.Programs[symbolToOverlay], symbolToOverlay,
		linkDir, netlink.HANDLE_MIN_EGRESS, option.Config.EnableTCX); err != nil {
		return fmt.Errorf("interface %s egress: %w", device, err)
	}

	if err := commit(); err != nil {
		return fmt.Errorf("committing bpf pins: %w", err)
	}

	return nil
}

func (l *loader) replaceWireguardDatapath(ctx context.Context, cArgs []string, iface string) (err error) {
	if err := compileWireguard(ctx, cArgs); err != nil {
		return fmt.Errorf("compiling wireguard program: %w", err)
	}
	device, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("retrieving device %s: %w", iface, err)
	}

	spec, err := bpf.LoadCollectionSpec(wireguardObj)
	if err != nil {
		return fmt.Errorf("loading eBPF ELF %s: %w", wireguardObj, err)
	}

	coll, commit, err := loadDatapath(spec, nil, nil)
	if err != nil {
		return err
	}
	defer coll.Close()

	linkDir := bpffsDeviceLinksDir(bpf.CiliumPath(), device)
	if err := attachSKBProgram(device, coll.Programs[symbolToWireguard], symbolToWireguard,
		linkDir, netlink.HANDLE_MIN_EGRESS, option.Config.EnableTCX); err != nil {
		return fmt.Errorf("interface %s egress: %w", device, err)
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
func (l *loader) ReloadDatapath(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) (hash string, err error) {
	dirs := directoryInfo{
		Library: option.Config.BpfDir,
		Runtime: option.Config.StateDir,
		State:   ep.StateDir(),
		Output:  ep.StateDir(),
	}

	cfg := l.nodeConfig.Load()

	spec, hash, err := l.templateCache.fetchOrCompile(ctx, cfg, ep, &dirs, stats)
	if err != nil {
		return "", err
	}

	stats.BpfLoadProg.Start()
	err = l.reloadDatapath(ep, spec)
	stats.BpfLoadProg.End(err == nil)
	return hash, err
}

// Unload removes the datapath specific program aspects
func (l *loader) Unload(ep datapath.Endpoint) {
	if ep.RequireEndpointRoute() {
		if ip := ep.IPv4Address(); ip.IsValid() {
			removeEndpointRoute(ep, *iputil.AddrToIPNet(ip))
		}

		if ip := ep.IPv6Address(); ip.IsValid() {
			removeEndpointRoute(ep, *iputil.AddrToIPNet(ip))
		}
	}

	log := log.WithField(logfields.EndpointID, ep.StringID())

	// Remove legacy tc attachments.
	link, err := netlink.LinkByName(ep.InterfaceName())
	if err == nil {
		if err := removeTCFilters(link, netlink.HANDLE_MIN_INGRESS); err != nil {
			log.WithError(err).Errorf("Removing ingress filter from interface %s", ep.InterfaceName())
		}
		if err := removeTCFilters(link, netlink.HANDLE_MIN_EGRESS); err != nil {
			log.WithError(err).Errorf("Removing egress filter from interface %s", ep.InterfaceName())
		}
	}

	// If Cilium and the kernel support tcx to attach TC programs to the
	// endpoint's veth device, its bpf_link object is pinned to a per-endpoint
	// bpffs directory. When the endpoint gets deleted, we can remove the whole
	// directory to clean up any leftover pinned links and maps.

	// Remove the links directory first to avoid removing program arrays before
	// the entrypoints are detached.
	if err := bpf.Remove(bpffsEndpointLinksDir(bpf.CiliumPath(), ep)); err != nil {
		log.WithError(err)
	}
	// Finally, remove the endpoint's top-level directory.
	if err := bpf.Remove(bpffsEndpointDir(bpf.CiliumPath(), ep)); err != nil {
		log.WithError(err)
	}
}

// EndpointHash hashes the specified endpoint configuration with the current
// datapath hash cache and returns the hash as string.
func (l *loader) EndpointHash(cfg datapath.EndpointConfiguration) (string, error) {
	return l.templateCache.baseHash.hashEndpoint(l.templateCache, l.nodeConfig.Load(), cfg)
}

// CallsMapPath gets the BPF Calls Map for the endpoint with the specified ID.
func (l *loader) CallsMapPath(id uint16) string {
	return bpf.LocalMapPath(callsmap.MapName, id)
}

// CustomCallsMapPath gets the BPF Custom Calls Map for the endpoint with the
// specified ID.
func (l *loader) CustomCallsMapPath(id uint16) string {
	return bpf.LocalMapPath(callsmap.CustomCallsMapName, id)
}

// HostDatapathInitialized returns a channel which is closed when the
// host datapath has been loaded for the first time.
func (l *loader) HostDatapathInitialized() <-chan struct{} {
	return l.hostDpInitialized
}

func (l *loader) WriteEndpointConfig(w io.Writer, e datapath.EndpointConfiguration) error {
	return l.configWriter.WriteEndpointConfig(w, l.nodeConfig.Load(), e)
}
