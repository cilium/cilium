// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/callsmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
	wgtypes "github.com/cilium/cilium/pkg/wireguard/types"
)

const (
	symbolFromHostEp = "cil_from_host"
	symbolToHostEp   = "cil_to_host"

	symbolFromHostNetdevEp = "cil_from_netdev"
	symbolToHostNetdevEp   = "cil_to_netdev"
)

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

	cfg.EphemeralMin = lnc.EphemeralMin

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

	cfg.EphemeralMin = lnc.EphemeralMin

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

	cfg.EphemeralMin = lnc.EphemeralMin

	renames := map[string]string{
		// Rename the calls map to include the device's ifindex.
		"cilium_calls": bpf.LocalMapName(callsmap.NetdevMapName, uint16(ifindex)),
		// Rename the policy map to include the host's endpoint id.
		"cilium_policy_v2": bpf.LocalMapName(policymap.MapName, uint16(ep.GetID())),
	}

	return cfg, renames
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
