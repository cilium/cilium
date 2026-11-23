// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/device"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/defaults"
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
