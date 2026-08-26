// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package device

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	mtuconst "github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/option"
)

// EnableForwarding puts the given link into the up state and enables IP forwarding.
func EnableForwarding(logger *slog.Logger, sysctl sysctl.Sysctl, link netlink.Link) error {
	ifName := link.Attrs().Name

	if err := netlink.LinkSetUp(link); err != nil {
		logger.Warn("Could not set up the link",
			logfields.Error, err,
			logfields.Device, ifName,
		)
		return fmt.Errorf("failed to set link up: %w", err)
	}

	sysSettings := make([]tables.Sysctl, 0, 5)
	if option.Config.EnableIPv6 {
		sysSettings = append(sysSettings, tables.Sysctl{
			Name: []string{"net", "ipv6", "conf", ifName, "forwarding"}, Val: "1", IgnoreErr: false})
	}
	if option.Config.EnableIPv4 {
		sysSettings = append(sysSettings, []tables.Sysctl{
			{Name: []string{"net", "ipv4", "conf", ifName, "forwarding"}, Val: "1", IgnoreErr: false},
			{Name: []string{"net", "ipv4", "conf", ifName, "rp_filter"}, Val: "0", IgnoreErr: false},
			{Name: []string{"net", "ipv4", "conf", ifName, "accept_local"}, Val: "1", IgnoreErr: false},
			{Name: []string{"net", "ipv4", "conf", ifName, "send_redirects"}, Val: "0", IgnoreErr: false},
		}...)
	}
	if err := sysctl.ApplySettings(sysSettings); err != nil {
		return fmt.Errorf("failed to apply sysctl settings for %s: %w", ifName, err)
	}

	return nil
}

// RemoveDevice removes the device with the given name. Returns error if the
// device exists but was unable to be removed.
func RemoveDevice(name string) error {
	link, err := safenetlink.LinkByName(name)
	if err != nil {
		return nil
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("removing device %s: %w", name, err)
	}

	return nil
}

// EnsureDevice ensures a device with the given attrs is present on the system.
// If a device with the given name already exists, device creation is skipped and
// the existing device will be used as-is for the subsequent configuration steps.
// The device is never recreated.
//
// The device's state is set to 'up', L3 forwarding sysctls are applied, and MTU
// is set.
func EnsureDevice(logger *slog.Logger, sysctl sysctl.Sysctl, attrs netlink.Link) (netlink.Link, error) {
	name := attrs.Attrs().Name

	// Reuse existing tunnel interface created by previous runs.
	l, err := safenetlink.LinkByName(name)
	if err != nil {
		if err := netlink.LinkAdd(attrs); err != nil {
			if errors.Is(err, unix.ENOTSUP) {
				err = fmt.Errorf("%w, maybe kernel module for %s is not available?", err, attrs.Type())
			}
			return nil, fmt.Errorf("creating device %s: %w", name, err)
		}

		// Fetch the link we've just created.
		l, err = safenetlink.LinkByName(name)
		if err != nil {
			return nil, fmt.Errorf("retrieving created device %s: %w", name, err)
		}
	}

	if err := EnableForwarding(logger, sysctl, l); err != nil {
		return nil, fmt.Errorf("setting up device %s: %w", name, err)
	}

	// Update MTU on the link if necessary.
	wantMTU, gotMTU := attrs.Attrs().MTU, l.Attrs().MTU
	if wantMTU != 0 && wantMTU != gotMTU {
		if err := netlink.LinkSetMTU(l, wantMTU); err != nil {
			return nil, fmt.Errorf("setting MTU on %s: %w", name, err)
		}
	}

	return l, nil
}

// SetupIPIPDevices ensures the specified v4 and/or v6 devices are created and
// configured with their respective sysctls.
//
// Calling this function may result in tunl0 (v4) or ip6tnl0 (v6) fallback
// interfaces being created as a result of loading the ipip and ip6_tunnel
// kernel modules by creating cilium_ tunnel interfaces. These are catch-all
// interfaces for the ipip decapsulation stack. By default, these interfaces
// will be created in new network namespaces, but Cilium disables this behaviour
// by setting net.core.fb_tunnels_only_for_init_net = 2.
//
// In versions of Cilium prior to 1.15, the behaviour was as follows:
//   - Repurpose the default tunl0 by setting it into collect_md mode and renaming
//     it to cilium_ipip4. Use the interface for production traffic.
//   - The same cannot be done for ip6tunl0, as collect_md cannot be enabled on
//     this interface. Leave it unused.
//   - Rename sit0 to cilium_sit, if present. This was potentially a mistake,
//     as the sit module is not involved with ip6tnl interfaces.
//
// As of Cilium 1.15, if present, tunl0 is renamed to cilium_tunl and ip6tnl0 is
// renamed to cilium_ip6tnl. This is to communicate to the user that Cilium has
// taken control of the encapsulation stack on the node, as it currently doesn't
// explicitly support sharing it with other tools/CNIs. Fallback devices are left
// unused for production traffic. Only devices that were explicitly created are
// used. As of Cilium 1.18, cilium_tunl and cilium_ip6tnl are not created anymore.
func SetupIPIPDevices(logger *slog.Logger, sysctl sysctl.Sysctl, ipv4, ipv6 bool, mtu int) error {
	// This setting needs to be applied before creating the IPIP devices.
	sysIPIP := []tables.Sysctl{
		{Name: []string{"net", "core", "fb_tunnels_only_for_init_net"}, Val: "2", IgnoreErr: true},
	}
	if err := sysctl.ApplySettings(sysIPIP); err != nil {
		return err
	}
	// FlowBased sets IFLA_IPTUN_COLLECT_METADATA, the equivalent of 'ip link add
	// ... type ipip/ip6tnl external'. This is needed so bpf programs can use
	// bpf_skb_[gs]et_tunnel_key() on packets flowing through tunnels.
	if ipv4 {
		dev := &netlink.Iptun{
			LinkAttrs: netlink.LinkAttrs{
				Name: defaults.IPIPv4Device,
				MTU:  mtu - mtuconst.IPIPv4Overhead,
			},
			FlowBased: true,
		}

		if _, err := EnsureDevice(logger, sysctl, dev); err != nil {
			return fmt.Errorf("creating %s: %w", defaults.IPIPv4Device, err)
		}

		// Rename fallback device created by potential kernel module load after
		// creating tunnel interface.
		if err := renameDevice("tunl0", "cilium_tunl"); err != nil {
			return fmt.Errorf("renaming fallback device %s: %w", "tunl0", err)
		}
	} else {
		if err := RemoveDevice(defaults.IPIPv4Device); err != nil {
			return fmt.Errorf("removing %s: %w", defaults.IPIPv4Device, err)
		}
	}

	if ipv6 {
		dev := &netlink.Ip6tnl{
			LinkAttrs: netlink.LinkAttrs{
				Name: defaults.IPIPv6Device,
				MTU:  mtu - mtuconst.IPIPv6Overhead,
			},
			FlowBased: true,
		}

		if _, err := EnsureDevice(logger, sysctl, dev); err != nil {
			return fmt.Errorf("creating %s: %w", defaults.IPIPv6Device, err)
		}

		// Rename fallback device created by potential kernel module load after
		// creating tunnel interface.
		if err := renameDevice("ip6tnl0", "cilium_ip6tnl"); err != nil {
			return fmt.Errorf("renaming fallback device %s: %w", "ip6tnl0", err)
		}
	} else {
		if err := RemoveDevice(defaults.IPIPv6Device); err != nil {
			return fmt.Errorf("removing %s: %w", defaults.IPIPv6Device, err)
		}
	}

	return nil
}

// renameDevice renames a network device from and to a given value. Returns nil
// if the device does not exist.
func renameDevice(from, to string) error {
	link, err := safenetlink.LinkByName(from)
	if err != nil {
		return nil
	}

	if err := netlink.LinkSetName(link, to); err != nil {
		return fmt.Errorf("renaming device %s to %s: %w", from, to, err)
	}

	return nil
}
