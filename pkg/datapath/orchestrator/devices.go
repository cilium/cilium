// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"fmt"
	"net"

	vnl "github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
)

// setupBaseDevice decides which and what kind of interfaces should be set up as
// the first step of datapath initialization, then performs the setup (and
// creation, if needed) of those interfaces. It returns two links and an error.
// By default, it sets up the veth pair - cilium_host and cilium_net.
func (o *orchestrator) setupBaseDevice() (vnl.Link, vnl.Link, error) {
	if err := o.setupVethPair(defaults.HostDevice, defaults.SecondHostDevice); err != nil {
		return nil, nil, err
	}

	linkHost, err := o.params.Netlink.LinkByName(defaults.HostDevice)
	if err != nil {
		return nil, nil, err
	}
	linkNet, err := o.params.Netlink.LinkByName(defaults.SecondHostDevice)
	if err != nil {
		return nil, nil, err
	}

	if err := o.params.Netlink.LinkSetARPOff(linkHost); err != nil {
		return nil, nil, err
	}
	if err := o.params.Netlink.LinkSetARPOff(linkNet); err != nil {
		return nil, nil, err
	}

	mtu := o.params.Mtu.GetDeviceMTU()
	if err := o.params.Netlink.LinkSetMTU(linkHost, mtu); err != nil {
		return nil, nil, err
	}
	if err := o.params.Netlink.LinkSetMTU(linkNet, mtu); err != nil {
		return nil, nil, err
	}

	return linkHost, linkNet, nil
}

func (o *orchestrator) setupVethPair(name, peerName string) error {
	// Create the veth pair if it doesn't exist.
	if _, err := o.params.Netlink.LinkByName(name); err != nil {
		hostMac, err := mac.GenerateRandMAC()
		if err != nil {
			return err
		}
		peerMac, err := mac.GenerateRandMAC()
		if err != nil {
			return err
		}

		veth := &vnl.Veth{
			LinkAttrs: vnl.LinkAttrs{
				Name:         name,
				HardwareAddr: net.HardwareAddr(hostMac),
				TxQLen:       1000,
			},
			PeerName:         peerName,
			PeerHardwareAddr: net.HardwareAddr(peerMac),
		}
		if err := o.params.Netlink.LinkAdd(veth); err != nil {
			return err
		}
	}

	veth, err := o.params.Netlink.LinkByName(name)
	if err != nil {
		return err
	}
	if err := o.enableForwarding(veth); err != nil {
		return err
	}
	peer, err := o.params.Netlink.LinkByName(peerName)
	if err != nil {
		return err
	}
	if err := o.enableForwarding(peer); err != nil {
		return err
	}

	return nil
}

// enableForwarding puts the given link into the up state and enables IP forwarding.
func (o *orchestrator) enableForwarding(link vnl.Link) error {
	ifName := link.Attrs().Name

	if err := o.params.Netlink.LinkSetUp(link); err != nil {
		o.params.Logger.WithError(err).WithField("device", ifName).Warn("Could not set up the link")
		return err
	}

	sysSettings := make([]tables.Sysctl, 0, 5)
	if option.Config.EnableIPv6 {
		sysSettings = append(sysSettings, tables.Sysctl{
			Name: fmt.Sprintf("net.ipv6.conf.%s.forwarding", ifName), Val: "1", IgnoreErr: false})
	}
	if option.Config.EnableIPv4 {
		sysSettings = append(sysSettings, []tables.Sysctl{
			{Name: fmt.Sprintf("net.ipv4.conf.%s.forwarding", ifName), Val: "1", IgnoreErr: false},
			{Name: fmt.Sprintf("net.ipv4.conf.%s.rp_filter", ifName), Val: "0", IgnoreErr: false},
			{Name: fmt.Sprintf("net.ipv4.conf.%s.accept_local", ifName), Val: "1", IgnoreErr: false},
			{Name: fmt.Sprintf("net.ipv4.conf.%s.send_redirects", ifName), Val: "0", IgnoreErr: false},
		}...)
	}
	if err := o.params.Sysctl.ApplySettings(sysSettings); err != nil {
		return err
	}

	return nil
}

// addHostDeviceAddr add internal ipv4 and ipv6 addresses to the cilium_host device.
func (o *orchestrator) addHostDeviceAddr(hostDev vnl.Link, ipv4, ipv6 net.IP) error {
	if ipv4 != nil {
		addr := vnl.Addr{
			IPNet: &net.IPNet{
				IP:   ipv4,
				Mask: net.CIDRMask(32, 32), // corresponds to /32
			},
		}

		if err := o.params.Netlink.AddrReplace(hostDev, &addr); err != nil {
			return err
		}
	}
	if ipv6 != nil {
		addr := vnl.Addr{
			IPNet: &net.IPNet{
				IP:   ipv6,
				Mask: net.CIDRMask(128, 128), // corresponds to /128
			},
		}

		if err := o.params.Netlink.AddrReplace(hostDev, &addr); err != nil {
			return err
		}

	}
	return nil
}

// setupTunnelDevice ensures the cilium_{mode} device is created and
// unused leftover devices are cleaned up in case mode changes.
func (o *orchestrator) setupTunnelDevice(cfg tunnel.Config) error {
	switch cfg.Protocol() {
	case tunnel.Geneve:
		if err := o.setupGeneveDevice(cfg); err != nil {
			return fmt.Errorf("setting up geneve device: %w", err)
		}
		if err := o.removeDevice(defaults.VxlanDevice); err != nil {
			return fmt.Errorf("removing %s: %w", defaults.VxlanDevice, err)
		}

	case tunnel.VXLAN:
		if err := o.setupVxlanDevice(cfg); err != nil {
			return fmt.Errorf("setting up vxlan device: %w", err)
		}
		if err := o.removeDevice(defaults.GeneveDevice); err != nil {
			return fmt.Errorf("removing %s: %w", defaults.GeneveDevice, err)
		}

	default:
		if err := o.removeDevice(defaults.VxlanDevice); err != nil {
			return fmt.Errorf("removing %s: %w", defaults.VxlanDevice, err)
		}
		if err := o.removeDevice(defaults.GeneveDevice); err != nil {
			return fmt.Errorf("removing %s: %w", defaults.GeneveDevice, err)
		}
	}

	return nil
}

// setupGeneveDevice ensures the cilium_geneve device is created with the given
// destination port and mtu.
//
// Changing the destination port will recreate the device. Changing the MTU will
// modify the device without recreating it.
func (o *orchestrator) setupGeneveDevice(cfg tunnel.Config) error {
	mac, err := mac.GenerateRandMAC()
	if err != nil {
		return err
	}

	dev := &vnl.Geneve{
		LinkAttrs: vnl.LinkAttrs{
			Name:         defaults.GeneveDevice,
			MTU:          o.params.Mtu.GetDeviceMTU(),
			HardwareAddr: net.HardwareAddr(mac),
		},
		FlowBased: true,
		Dport:     cfg.Port(),
	}

	l, err := o.ensureDevice(dev)
	if err != nil {
		return fmt.Errorf("creating geneve device: %w", err)
	}

	// Recreate the device with the correct destination port. Modifying the device
	// without recreating it is not supported.
	geneve, _ := l.(*vnl.Geneve)
	if geneve.Dport != cfg.Port() {
		if err := o.params.Netlink.LinkDel(l); err != nil {
			return fmt.Errorf("deleting outdated geneve device: %w", err)
		}
		if _, err := o.ensureDevice(dev); err != nil {
			return fmt.Errorf("recreating geneve device %s: %w", defaults.GeneveDevice, err)
		}
	}

	return nil
}

// setupVxlanDevice ensures the cilium_vxlan device is created with the given
// port and mtu.
//
// Changing the port will recreate the device. Changing the MTU will modify the
// device without recreating it.
func (o *orchestrator) setupVxlanDevice(cfg tunnel.Config) error {
	mac, err := mac.GenerateRandMAC()
	if err != nil {
		return err
	}

	dev := &vnl.Vxlan{
		LinkAttrs: vnl.LinkAttrs{
			Name:         defaults.VxlanDevice,
			MTU:          o.params.Mtu.GetDeviceMTU(),
			HardwareAddr: net.HardwareAddr(mac),
		},
		FlowBased: true,
		Port:      int(cfg.Port()),
	}

	l, err := o.ensureDevice(dev)
	if err != nil {
		return fmt.Errorf("creating vxlan device: %w", err)
	}

	// Recreate the device with the correct destination port. Modifying the device
	// without recreating it is not supported.
	vxlan, _ := l.(*vnl.Vxlan)
	if vxlan.Port != int(cfg.Port()) {
		if err := vnl.LinkDel(l); err != nil {
			return fmt.Errorf("deleting outdated vxlan device: %w", err)
		}
		if _, err := o.ensureDevice(dev); err != nil {
			return fmt.Errorf("recreating vxlan device %s: %w", defaults.VxlanDevice, err)
		}
	}

	return nil
}

// setupIPIPDevices ensures the specified v4 and/or v6 devices are created and
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
// unused for production traffic. Only devices that were explicitly created are used.
func (o *orchestrator) setupIPIPDevices(ipv4, ipv6 bool) error {
	// FlowBased sets IFLA_IPTUN_COLLECT_METADATA, the equivalent of 'ip link add
	// ... type ipip/ip6tnl external'. This is needed so bpf programs can use
	// bpf_skb_[gs]et_tunnel_key() on packets flowing through tunnels.

	if ipv4 {
		// Set up IPv4 tunnel device if requested.
		if _, err := o.ensureDevice(&vnl.Iptun{
			LinkAttrs: vnl.LinkAttrs{Name: defaults.IPIPv4Device},
			FlowBased: true,
		}); err != nil {
			return fmt.Errorf("creating %s: %w", defaults.IPIPv4Device, err)
		}

		// Rename fallback device created by potential kernel module load after
		// creating tunnel interface.
		if err := o.renameDevice("tunl0", "cilium_tunl"); err != nil {
			return fmt.Errorf("renaming fallback device %s: %w", "tunl0", err)
		}
	} else {
		if err := o.removeDevice(defaults.IPIPv4Device); err != nil {
			return fmt.Errorf("removing %s: %w", defaults.IPIPv4Device, err)
		}
	}

	if ipv6 {
		// Set up IPv6 tunnel device if requested.
		if _, err := o.ensureDevice(&vnl.Ip6tnl{
			LinkAttrs: vnl.LinkAttrs{Name: defaults.IPIPv6Device},
			FlowBased: true,
		}); err != nil {
			return fmt.Errorf("creating %s: %w", defaults.IPIPv6Device, err)
		}

		// Rename fallback device created by potential kernel module load after
		// creating tunnel interface.
		if err := o.renameDevice("ip6tnl0", "cilium_ip6tnl"); err != nil {
			return fmt.Errorf("renaming fallback device %s: %w", "tunl0", err)
		}
	} else {
		if err := o.removeDevice(defaults.IPIPv6Device); err != nil {
			return fmt.Errorf("removing %s: %w", defaults.IPIPv6Device, err)
		}
	}

	return nil
}

// ensureDevice ensures a device with the given attrs is present on the system.
// If a device with the given name already exists, device creation is skipped and
// the existing device will be used as-is for the subsequent configuration steps.
// The device is never recreated.
//
// The device's state is set to 'up', L3 forwarding sysctls are applied, and MTU
// is set.
func (o *orchestrator) ensureDevice(attrs vnl.Link) (vnl.Link, error) {
	name := attrs.Attrs().Name

	// Reuse existing tunnel interface created by previous runs.
	l, err := o.params.Netlink.LinkByName(name)
	if err != nil {
		if err := o.params.Netlink.LinkAdd(attrs); err != nil {
			return nil, fmt.Errorf("creating device %s: %w", name, err)
		}

		// Fetch the link we've just created.
		l, err = o.params.Netlink.LinkByName(name)
		if err != nil {
			return nil, fmt.Errorf("retrieving created device %s: %w", name, err)
		}
	}

	if err := o.enableForwarding(l); err != nil {
		return nil, fmt.Errorf("setting up device %s: %w", name, err)
	}

	// Update MTU on the link if necessary.
	wantMTU, gotMTU := attrs.Attrs().MTU, l.Attrs().MTU
	if wantMTU != 0 && wantMTU != gotMTU {
		if err := o.params.Netlink.LinkSetMTU(l, wantMTU); err != nil {
			return nil, fmt.Errorf("setting MTU on %s: %w", name, err)
		}
	}

	return l, nil
}

// removeDevice removes the device with the given name. Returns error if the
// device exists but was unable to be removed.
func (o *orchestrator) removeDevice(name string) error {
	link, err := o.params.Netlink.LinkByName(name)
	if err != nil {
		return nil
	}

	if err := o.params.Netlink.LinkDel(link); err != nil {
		return fmt.Errorf("removing device %s: %w", name, err)
	}

	return nil
}

// renameDevice renames a network device from and to a given value. Returns nil
// if the device does not exist.
func (o *orchestrator) renameDevice(from, to string) error {
	link, err := o.params.Netlink.LinkByName(from)
	if err != nil {
		return nil
	}

	if err := o.params.Netlink.LinkSetName(link, to); err != nil {
		return fmt.Errorf("renaming device %s to %s: %w", from, to, err)
	}

	return nil
}

func (o *orchestrator) cleanIngressQdisc() error {
	rx := o.params.DB.ReadTxn()
	devices, _ := tables.SelectedDevices(o.params.DeviceTbl, rx)
	for _, iface := range devices {
		link, err := o.params.Netlink.LinkByName(iface.Name)
		if err != nil {
			return fmt.Errorf("failed to retrieve link %s by name: %q", iface.Name, err)
		}
		qdiscs, err := o.params.Netlink.QdiscList(link)
		if err != nil {
			return fmt.Errorf("failed to retrieve qdisc list of link %s: %q", iface.Name, err)
		}
		for _, q := range qdiscs {
			if q.Type() != "ingress" {
				continue
			}
			err = o.params.Netlink.QdiscDel(q)
			if err != nil {
				return fmt.Errorf("failed to delete ingress qdisc of link %s: %q", iface.Name, err)
			} else {
				o.params.Logger.WithField(logfields.Device, iface.Name).Info("Removed prior present ingress qdisc from device so that Cilium's datapath can be loaded")
			}
		}
	}
	return nil
}
