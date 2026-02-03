// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"fmt"
	"log/slog"
	"net/netip"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/callsmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
)

func init() {
	ciliumHostConfigs.register(config.CiliumHost)
	ciliumHostRenames.register(defaultCiliumHostMapRenames)
	ciliumNetConfigs.register(config.CiliumNet)
	ciliumNetRenames.register(defaultCiliumNetMapRenames)
	netdevConfigs.register(config.Netdev)
	netdevRenames.register(defaultNetdevMapRenames)
}

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

// ciliumHostConfigs holds functions that yield a BPF configuration object for
// cilium_host.
var ciliumHostConfigs funcRegistry[func(datapath.EndpointConfiguration, *datapath.LocalNodeConfiguration) any]

// ciliumHostRenames holds functions that yield BPF map renames for cilium_host.
var ciliumHostRenames funcRegistry[func(datapath.EndpointConfiguration, *datapath.LocalNodeConfiguration) map[string]string]

// ciliumHostConfiguration returns a slice of host configuration objects yielded
// by all registered config providers of [ciliumHostConfigs].
func ciliumHostConfiguration(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration) (configs []any) {
	for f := range ciliumHostConfigs.all() {
		configs = append(configs, f(ep, lnc))
	}
	return configs
}

// ciliumHostMapRenames returns the merged map of host map renames yielded by all registered rename providers.
func ciliumHostMapRenames(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration) (renames []map[string]string) {
	for f := range ciliumHostRenames.all() {
		renames = append(renames, f(ep, lnc))
	}
	return renames
}

func defaultCiliumHostMapRenames(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration) map[string]string {
	return map[string]string{
		// Rename calls and policy maps to include the host endpoint's id.
		"cilium_calls":     bpf.LocalMapName(callsmap.HostMapName, uint16(ep.GetID())),
		"cilium_policy_v2": bpf.LocalMapName(policymap.MapName, uint16(ep.GetID())),
	}
}

// attachCiliumHost inserts the host endpoint's policy program into the global
// cilium_call_policy map and attaches programs from bpf_host.c to cilium_host.
func attachCiliumHost(logger *slog.Logger, ep datapath.Endpoint, lnc *datapath.LocalNodeConfiguration, spec *ebpf.CollectionSpec) error {
	host, err := safenetlink.LinkByName(ep.InterfaceName())
	if err != nil {
		return fmt.Errorf("retrieving device %s: %w", ep.InterfaceName(), err)
	}

	var hostObj hostObjects
	commit, err := bpf.LoadAndAssign(logger, &hostObj, spec, &bpf.CollectionOptions{
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
		},
		Constants:      ciliumHostConfiguration(ep, lnc),
		MapRenames:     ciliumHostMapRenames(ep, lnc),
		ConfigDumpPath: filepath.Join(bpfStateDeviceDir(ep.InterfaceName()), hostEndpointConfig),
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

// ciliumNetConfigs holds functions that yield a BPF configuration object for
// cilium_net.
var ciliumNetConfigs funcRegistry[func(datapath.EndpointConfiguration, *datapath.LocalNodeConfiguration, netlink.Link) any]

// ciliumNetRenames holds functions that yield BPF map renames for cilium_net.
var ciliumNetRenames funcRegistry[func(datapath.EndpointConfiguration, *datapath.LocalNodeConfiguration, netlink.Link) map[string]string]

// ciliumNetConfiguration returns a slice of BPF configuration objects yielded
// by all registered config providers of [ciliumNetConfigs].
func ciliumNetConfiguration(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration, link netlink.Link) (configs []any) {
	for f := range ciliumNetConfigs.all() {
		configs = append(configs, f(ep, lnc, link))
	}
	return configs
}

// ciliumHostMapRenames returns the merged map of cilium_net map renames yielded by all registered rename providers.
func ciliumNetMapRenames(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration, link netlink.Link) (renames []map[string]string) {
	for f := range ciliumNetRenames.all() {
		renames = append(renames, f(ep, lnc, link))
	}
	return renames
}

func defaultCiliumNetMapRenames(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration, link netlink.Link) map[string]string {
	return map[string]string{
		// Rename the calls map to include cilium_net's ifindex.
		"cilium_calls": bpf.LocalMapName(callsmap.NetdevMapName, uint16(link.Attrs().Index)),
		// Rename the policy map to include the host endpoint's id.
		"cilium_policy_v2": bpf.LocalMapName(policymap.MapName, uint16(ep.GetID())),
	}
}

// attachCiliumNet attaches programs from bpf_host.c to cilium_net.
func attachCiliumNet(logger *slog.Logger, ep datapath.Endpoint, lnc *datapath.LocalNodeConfiguration, spec *ebpf.CollectionSpec) error {
	net, err := safenetlink.LinkByName(defaults.SecondHostDevice)
	if err != nil {
		return fmt.Errorf("retrieving device %s: %w", defaults.SecondHostDevice, err)
	}

	var netObj hostNetObjects
	commit, err := bpf.LoadAndAssign(logger, &netObj, spec, &bpf.CollectionOptions{
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
		},
		Constants:      ciliumNetConfiguration(ep, lnc, net),
		MapRenames:     ciliumNetMapRenames(ep, lnc, net),
		ConfigDumpPath: filepath.Join(bpfStateDeviceDir(defaults.SecondHostDevice), hostEndpointConfig),
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

// netdevConfigs holds functions that yield a BPF configuration object for
// attaching instances of bpf_host.c to externally-facing network devices.
var netdevConfigs funcRegistry[func(datapath.EndpointConfiguration, *datapath.LocalNodeConfiguration, netlink.Link, netip.Addr, netip.Addr) any]

// netdevRenames holds functions that yield BPF map renames for
// attaching instances of bpf_host.c to externally-facing network devices.
var netdevRenames funcRegistry[func(datapath.EndpointConfiguration, *datapath.LocalNodeConfiguration, netlink.Link) map[string]string]

// netdevConfiguration returns a slice of host configuration objects yielded
// by all registered config providers of [netdevConfigs].
func netdevConfiguration(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration, link netlink.Link, masq4, masq6 netip.Addr) (configs []any) {
	for f := range netdevConfigs.all() {
		configs = append(configs, f(ep, lnc, link, masq4, masq6))
	}
	return configs
}

// netdevMapRenames returns the merged map of netdev map renames yielded by all registered rename providers.
func netdevMapRenames(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration, link netlink.Link) (renames []map[string]string) {
	for f := range netdevRenames.all() {
		renames = append(renames, f(ep, lnc, link))
	}
	return renames
}

func defaultNetdevMapRenames(ep datapath.EndpointConfiguration, lnc *datapath.LocalNodeConfiguration, link netlink.Link) map[string]string {
	return map[string]string{
		// Rename the calls map to include the device's ifindex.
		"cilium_calls": bpf.LocalMapName(callsmap.NetdevMapName, uint16(link.Attrs().Index)),
		// Rename the policy map to include the host's endpoint id.
		"cilium_policy_v2": bpf.LocalMapName(policymap.MapName, uint16(ep.GetID())),
	}
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
	if option.Config.EnableIPIPTermination && !option.Config.UnsafeDaemonConfigOption.EnableHealthDatapath {
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
		masq4, masq6 := bpfMasqAddrs(iface.Attrs().Name, lnc,
			option.Config.EnableIPv4Masquerade, option.Config.EnableIPv6Masquerade)

		var netdevObj hostNetdevObjects
		commit, err := bpf.LoadAndAssign(logger, &netdevObj, spec, &bpf.CollectionOptions{
			CollectionOptions: ebpf.CollectionOptions{
				Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
			},
			Constants:      netdevConfiguration(ep, lnc, iface, masq4, masq6),
			MapRenames:     netdevMapRenames(ep, lnc, iface),
			ConfigDumpPath: filepath.Join(bpfStateDeviceDir(iface.Attrs().Name), hostEndpointConfig),
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
