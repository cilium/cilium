// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"fmt"
	"log/slog"
	"math"
	"net"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/bigtcp"
	"github.com/cilium/cilium/pkg/datapath/linux/device"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
)

const qdiscClsact = "clsact"

func directionToParent(dir string) uint32 {
	switch dir {
	case dirIngress:
		return netlink.HANDLE_MIN_INGRESS
	case dirEgress:
		return netlink.HANDLE_MIN_EGRESS
	}
	return 0
}

func setupVethPair(logger *slog.Logger, sysctl sysctl.Sysctl, name, peerName string) error {
	// Create the veth pair if it doesn't exist.
	if _, err := safenetlink.LinkByName(name); err != nil {
		hostMac, err := mac.GenerateRandMAC()
		if err != nil {
			return fmt.Errorf("failed to generate random MAC address for host: %w", err)
		}
		peerMac, err := mac.GenerateRandMAC()
		if err != nil {
			return fmt.Errorf("failed to generate random MAC address for peer: %w", err)
		}

		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name:         name,
				HardwareAddr: hostMac.HardwareAddr(),
				TxQLen:       1000,
			},
			PeerName:         peerName,
			PeerHardwareAddr: peerMac.HardwareAddr(),
		}
		if err := netlink.LinkAdd(veth); err != nil {
			return fmt.Errorf("failed to add veth pair: %w", err)
		}
	}

	veth, err := safenetlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to get link by name %s: %w", name, err)
	}
	peer, err := safenetlink.LinkByName(peerName)
	if err != nil {
		return fmt.Errorf("failed to get link by name %s: %w", peerName, err)
	}

	// Turn ARP off before bringing the links up. The kernel skips duplicate
	// address detection on NOARP devices, so the kernel-generated IPv6
	// link-local is added as permanent instead of spending up to a second in
	// the tentative state, invisible to netlink subscribers.
	if err := netlink.LinkSetARPOff(veth); err != nil {
		return fmt.Errorf("failed to set ARP off for %s: %w", name, err)
	}
	if err := netlink.LinkSetARPOff(peer); err != nil {
		return fmt.Errorf("failed to set ARP off for %s: %w", peerName, err)
	}

	if err := device.EnableForwarding(logger, sysctl, veth); err != nil {
		return fmt.Errorf("failed to enable forwarding on veth: %w", err)
	}
	if err := device.EnableForwarding(logger, sysctl, peer); err != nil {
		return fmt.Errorf("failed to enable forwarding on peer: %w", err)
	}

	return nil
}

// setupBaseDevice decides which and what kind of interfaces should be set up as
// the first step of datapath initialization, then performs the setup (and
// creation, if needed) of those interfaces. It returns two links and an error.
// By default, it sets up the veth pair - cilium_host and cilium_net.
func setupBaseDevice(logger *slog.Logger, sysctl sysctl.Sysctl, mtu int) (netlink.Link, netlink.Link, error) {
	if err := setupVethPair(logger, sysctl, defaults.HostDevice, defaults.SecondHostDevice); err != nil {
		return nil, nil, fmt.Errorf("failed to setup veth pair: %w", err)
	}

	linkHost, err := safenetlink.LinkByName(defaults.HostDevice)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get link for %s: %w", defaults.HostDevice, err)
	}
	linkNet, err := safenetlink.LinkByName(defaults.SecondHostDevice)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get link for %s: %w", defaults.SecondHostDevice, err)
	}

	if err := netlink.LinkSetMTU(linkHost, mtu); err != nil {
		return nil, nil, fmt.Errorf("failed to set MTU %d for %s: %w", mtu, linkHost.Attrs().Name, err)
	}
	if err := netlink.LinkSetMTU(linkNet, mtu); err != nil {
		return nil, nil, fmt.Errorf("failed to set MTU %d for %s: %w", mtu, linkNet.Attrs().Name, err)
	}

	return linkHost, linkNet, nil
}

// addHostDeviceAddr add internal ipv4 and ipv6 addresses to the cilium_host device.
func addHostDeviceAddr(hostDev netlink.Link, ipv4, ipv6 net.IP) error {
	if ipv4 != nil {
		addr := netlink.Addr{
			IPNet: &net.IPNet{
				IP:   ipv4,
				Mask: net.CIDRMask(32, 32), // corresponds to /32
			},
		}

		if err := netlink.AddrReplace(hostDev, &addr); err != nil {
			return fmt.Errorf("failed to replace IPv4 address: %w", err)
		}
	}
	if ipv6 != nil {
		addr := netlink.Addr{
			IPNet: &net.IPNet{
				IP:   ipv6,
				Mask: net.CIDRMask(128, 128), // corresponds to /128
			},
		}

		if err := netlink.AddrReplace(hostDev, &addr); err != nil {
			return fmt.Errorf("failed to replace IPv6 address: %w", err)
		}
	}
	return nil
}

// setupTunnelDevice ensures the cilium_{mode} device is created and
// unused leftover devices are cleaned up in case mode changes.
func setupTunnelDevice(logger *slog.Logger, sysctl sysctl.Sysctl, mode tunnel.EncapProtocol, port, srcPortLow, srcPortHigh uint16, mtu int, bigtcp bigtcp.Config) error {
	switch mode {
	case tunnel.Geneve:
		if err := setupGeneveDevice(logger, sysctl, port, srcPortLow, srcPortHigh, mtu); err != nil {
			return fmt.Errorf("setting up geneve device: %w", err)
		}
		if err := setupTunnelGSOGRO(logger, defaults.GeneveDevice, bigtcp); err != nil {
			return fmt.Errorf("setting up GSO/GRO on GENEVE netdev: %w", err)
		}
		if err := device.RemoveDevice(defaults.VxlanDevice); err != nil {
			return fmt.Errorf("removing %s: %w", defaults.VxlanDevice, err)
		}

	case tunnel.VXLAN:
		if err := setupVxlanDevice(logger, sysctl, port, srcPortLow, srcPortHigh, mtu); err != nil {
			return fmt.Errorf("setting up vxlan device: %w", err)
		}
		if err := setupTunnelGSOGRO(logger, defaults.VxlanDevice, bigtcp); err != nil {
			return fmt.Errorf("setting up GSO/GRO on VXLAN netdev: %w", err)
		}
		if err := device.RemoveDevice(defaults.GeneveDevice); err != nil {
			return fmt.Errorf("removing %s: %w", defaults.GeneveDevice, err)
		}

	default:
		if err := device.RemoveDevice(defaults.VxlanDevice); err != nil {
			return fmt.Errorf("removing %s: %w", defaults.VxlanDevice, err)
		}
		if err := device.RemoveDevice(defaults.GeneveDevice); err != nil {
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
func setupGeneveDevice(logger *slog.Logger, sysctl sysctl.Sysctl, dport, srcPortLow, srcPortHigh uint16, mtu int) error {
	mac, err := mac.GenerateRandMAC()
	if err != nil {
		return fmt.Errorf("failed to generate random MAC address for geneve device: %w", err)
	}
	// In geneve driver kernel defaults to [1,USHRT_MAX]
	if srcPortLow == 0 && srcPortHigh == 0 {
		srcPortLow = 1
		srcPortHigh = math.MaxUint16
	}

	dev := &netlink.Geneve{
		LinkAttrs: netlink.LinkAttrs{
			Name:         defaults.GeneveDevice,
			MTU:          mtu,
			HardwareAddr: mac.HardwareAddr(),
		},
		FlowBased: true,
		Dport:     dport,
		PortLow:   int(srcPortLow),
		PortHigh:  int(srcPortHigh),
	}

	l, err := device.EnsureDevice(logger, sysctl, dev)
	if err != nil {
		return fmt.Errorf("creating geneve device: %w", err)
	}

	// Recreate the device with the correct destination port. Modifying the device
	// without recreating it is not supported.
	geneve, _ := l.(*netlink.Geneve)
	if geneve.Dport != dport {
		if err := netlink.LinkDel(l); err != nil {
			return fmt.Errorf("deleting outdated geneve device: %w", err)
		}
		if _, err := device.EnsureDevice(logger, sysctl, dev); err != nil {
			return fmt.Errorf("recreating geneve device %s: %w", defaults.GeneveDevice, err)
		}
	}
	if geneve.PortLow != int(srcPortLow) || geneve.PortHigh != int(srcPortHigh) {
		logger.Info(
			"Source port range hint ignored given geneve device already exists",
			logfields.Hint, fmt.Sprintf("(%d-%d)", int(srcPortLow), int(srcPortHigh)),
			logfields.Range, fmt.Sprintf("(%d-%d)", geneve.PortLow, geneve.PortHigh),
			logfields.Device, defaults.GeneveDevice,
		)
	}
	return nil
}

// setupVxlanDevice ensures the cilium_vxlan device is created with the given
// port, source port range, and MTU.
//
// Changing the port will recreate the device. Changing the MTU will modify the
// device without recreating it. Changing the source port range at runtime is
// not possible, and it's also not worth to recreate. It's a best effort hint
// for first-time creation.
func setupVxlanDevice(logger *slog.Logger, sysctl sysctl.Sysctl, port, srcPortLow, srcPortHigh uint16, mtu int) error {
	mac, err := mac.GenerateRandMAC()
	if err != nil {
		return fmt.Errorf("failed to generate random MAC address for vxlan device: %w", err)
	}

	dev := &netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:         defaults.VxlanDevice,
			MTU:          mtu,
			HardwareAddr: mac.HardwareAddr(),
		},
		FlowBased: true,
		Port:      int(port),
		PortLow:   int(srcPortLow),
		PortHigh:  int(srcPortHigh),
	}

	// It's possible to create multiple vxlan devices with the same dstport,
	// though only one of them can be 'up'. Delete an existing vxlan device
	// with a mismatching port before attempting to create a new one to
	// avoid ensureDevice setting up the old interface. This avoids the
	// agent getting stuck if it conflicts with an unmanaged vxlan interface.
	if l, err := safenetlink.LinkByName(dev.Attrs().Name); err == nil {
		// Recreate the device with the correct destination port. Modifying the device
		// without recreating it is not supported.
		vxlan, _ := l.(*netlink.Vxlan)
		if vxlan.Port != int(port) {
			if err := netlink.LinkDel(l); err != nil {
				return fmt.Errorf("deleting outdated vxlan device: %w", err)
			}
		}
	}

	l, err := device.EnsureDevice(logger, sysctl, dev)
	if err != nil {
		return fmt.Errorf("creating vxlan device %s: %w", dev.Attrs().Name, err)
	}

	vxlan, _ := l.(*netlink.Vxlan)
	if vxlan.PortLow != int(srcPortLow) || vxlan.PortHigh != int(srcPortHigh) {
		logger.Info(
			"Source port range hint ignored given vxlan device already exists",
			logfields.Hint, fmt.Sprintf("(%d-%d)", int(srcPortLow), int(srcPortHigh)),
			logfields.Range, fmt.Sprintf("(%d-%d)", vxlan.PortLow, vxlan.PortHigh),
			logfields.Device, defaults.VxlanDevice,
		)
	}
	return nil
}

func setupTunnelGSOGRO(logger *slog.Logger, device string, bc bigtcp.Config) error {
	// IPv6 goes first, because {gso,gro}_ipv4_max_size gets auto-adjusted
	// if the new size of {gso,gro}_max_size isn't greater than 64KB for
	// backwards compatibility.
	if bc.GetGROIPv6MaxSize() != 0 && bc.GetGSOIPv6MaxSize() != 0 {
		logger.Info("Setting IPv6",
			logfields.Device, device,
			logfields.GsoMaxSize, bc.GetGSOIPv6MaxSize(),
			logfields.GroMaxSize, bc.GetGROIPv6MaxSize(),
		)
		err := bigtcp.SetGROGSOIPv6MaxSize(logger, device, bc.GetGROIPv6MaxSize(), bc.GetGSOIPv6MaxSize())
		if err != nil {
			logger.Warn("Could not modify IPv6 gro_max_size and gso_max_size",
				logfields.Device, device,
				logfields.Error, err)
			return err
		}
	}
	if bc.GetGROIPv4MaxSize() != 0 && bc.GetGSOIPv4MaxSize() != 0 {
		logger.Info("Setting IPv4",
			logfields.Device, device,
			logfields.GsoMaxSize, bc.GetGSOIPv4MaxSize(),
			logfields.GroMaxSize, bc.GetGROIPv4MaxSize(),
		)
		err := bigtcp.SetGROGSOIPv4MaxSize(logger, device, bc.GetGROIPv4MaxSize(), bc.GetGSOIPv4MaxSize())
		if err != nil {
			logger.Warn("Could not modify IPv4 gro_ipv4_max_size and gso_ipv4_max_size",
				logfields.Device, device,
				logfields.Error, err,
			)
			return err
		}
	}
	return nil
}

// DeviceHasSKBProgramLoaded returns true if the given device has a tc(x) program
// attached.
//
// If checkEgress is true, returns true if there's both an ingress and
// egress program attached.
func DeviceHasSKBProgramLoaded(device string, checkEgress bool) (bool, error) {
	link, err := safenetlink.LinkByName(device)
	if err != nil {
		return false, fmt.Errorf("retrieving device %s: %w", device, err)
	}

	itcx, err := hasCiliumTCXLinks(link, ebpf.AttachTCXIngress)
	if err != nil {
		return false, fmt.Errorf("failed to check for cilium tcx links on ingress: %w", err)
	}
	itc, err := hasCiliumTCFilters(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return false, fmt.Errorf("failed to check for cilium tc filters on ingress: %w", err)
	}
	ink, err := hasCiliumNetkitLinks(link, ebpf.AttachNetkitPeer)
	if err != nil {
		return false, fmt.Errorf("failed to check for cilium netkit links: %w", err)
	}

	// Need ingress programs at minimum, bail out if these are already missing.
	if !itc && !itcx && !ink {
		return false, nil
	}

	if !checkEgress {
		return true, nil
	}

	etcx, err := hasCiliumTCXLinks(link, ebpf.AttachTCXEgress)
	if err != nil {
		return false, fmt.Errorf("failed to check for cilium tcx links on egress: %w", err)
	}
	etc, err := hasCiliumTCFilters(link, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return false, fmt.Errorf("failed to check for cilium tc filters on egress: %w", err)
	}
	enk, err := hasCiliumNetkitLinks(link, ebpf.AttachNetkitPrimary)
	if err != nil {
		return false, fmt.Errorf("failed to check for cilium netkit links on primary: %w", err)
	}

	return etc || etcx || enk, nil
}
