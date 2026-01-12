// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
)

// setupNetkitPair sets up the host-facing interface, the peer interface and fills
// up some endpoint fields such as mac, NodeMac, ifIndex and ifName. Returns a pointer
// for the created netkit, a pointer for the peer link and error if something fails.
func setupNetkitPair(defaultLogger *slog.Logger, cfg types.LinkConfig, l2Mode bool, sysctl sysctl.Sysctl) (*netlink.Netkit, netlink.Link, error) {
	logger := defaultLogger.With(logfields.LogSubsys, "endpoint-connector")
	var epHostMAC, epLXCMAC mac.MAC
	var err error

	mode := netlink.NETKIT_MODE_L3
	if l2Mode {
		mode = netlink.NETKIT_MODE_L2
		// This is similar to the workaround used for veth.
		//
		// systemd 242+ tries to set a "persistent" MAC addr for any virtual
		// device by default (controlled by MACAddressPolicy). As setting
		// happens asynchronously after a device has been created, ep.Mac and
		// ep.HostMac can become stale which has a serious consequence - the
		// kernel will drop any packet sent to/from the endpoint. However, we
		// can trick systemd by explicitly setting MAC addrs for both veth ends.
		// This sets addr_assign_type for NET_ADDR_SET which prevents systemd
		// from changing the addrs.
		epHostMAC, err = mac.GenerateRandMAC()
		if err != nil {
			return nil, nil, fmt.Errorf("unable to generate host mac addr: %w", err)
		}
		epLXCMAC, err = mac.GenerateRandMAC()
		if err != nil {
			return nil, nil, fmt.Errorf("unable to generate peer mac addr: %w", err)
		}
	}
	netkit := &netlink.Netkit{
		LinkAttrs: netlink.LinkAttrs{
			Name:         cfg.HostIfName,
			TxQLen:       1000,
			HardwareAddr: net.HardwareAddr(epHostMAC),
		},
		Mode:       mode,
		Policy:     netlink.NETKIT_POLICY_FORWARD,
		PeerPolicy: netlink.NETKIT_POLICY_BLACKHOLE,
		// Disable scrubbing on the primary device to ensure that the mark is
		// preserved for cil_to_container when using endpoint routes.
		Scrub: netlink.NETKIT_SCRUB_NONE,
		// Ensure that packets leaving the pod's networking namespace are
		// scrubbed.
		PeerScrub: netlink.NETKIT_SCRUB_DEFAULT,
		// Configure the headroom and tailroom, which should be calculated to
		// appropriate values by the agent, taking into account things like
		// tunneling and encryption.
		DesiredHeadroom: uint16(cfg.DeviceHeadroom),
		DesiredTailroom: uint16(cfg.DeviceTailroom),
	}
	peerAttr := &netlink.LinkAttrs{
		Name:         cfg.PeerIfName,
		HardwareAddr: net.HardwareAddr(epLXCMAC),
	}
	netkit.SetPeerAttrs(peerAttr)

	err = netlink.LinkAdd(netkit)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create netkit pair: %w", err)
	}
	defer func() {
		if err != nil {
			if err = netlink.LinkDel(netkit); err != nil {
				logger.Warn("failed to clean up netkit",
					logfields.Error, err,
					logfields.Netkit, netkit.Name,
				)
			}
		}
	}()

	logger.Debug("Created netkit pair",
		logfields.NetkitPair, []string{cfg.HostIfName, cfg.PeerIfName},
		logfields.DeviceHeadroom, netkit.DesiredHeadroom,
		logfields.DeviceTailroom, netkit.DesiredTailroom,
	)

	// Disable reverse path filter on the host side netkit peer to allow
	// container addresses to be used as source address when the linux
	// stack performs routing.
	err = DisableRpFilter(sysctl, cfg.HostIfName)
	if err != nil {
		return nil, nil, err
	}

	peer, err := validateNetkitPair(logger, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("netkit validation failed: %w", err)
	}

	return netkit, peer, nil
}

// validateNetkitPair queries the kernel for a copy of the underlying device attributes
// for both the lxc host interface and the peer interface.
func validateNetkitPair(logger *slog.Logger, cfg types.LinkConfig) (netlink.Link, error) {
	// Query the kernel for the host link attributes, so we can verify the kernel
	// has applied the configuration we expected.
	hostLink, err := safenetlink.LinkByName(cfg.HostIfName)
	if err != nil {
		return nil, fmt.Errorf("unable to lookup netkit host link: %w", err)
	}

	hostDevice, ok := hostLink.(*netlink.Netkit)
	if !ok {
		return nil, fmt.Errorf("host link does not appear to be a Netkit device")
	}

	peerLink, err := safenetlink.LinkByName(cfg.PeerIfName)
	if err != nil {
		return nil, fmt.Errorf("unable to lookup netkit peer link: %w", err)
	}

	peerDevice, ok := peerLink.(*netlink.Netkit)
	if !ok {
		return nil, fmt.Errorf("peer link does not appear to be a Netkit device")
	}

	// Validate the kernel supports Scrub functionality.
	if !hostDevice.SupportsScrub() || !peerDevice.SupportsScrub() {
		logger.Warn("kernel does not support IFLA_NETKIT_SCRUB, some features may not work with netkit",
			logfields.NetkitPair, []string{hostDevice.Name, peerDevice.Name})
	}

	// Verify we have the correct buffer margins configured. We accept a margin that
	// is greater than what we requested, just in case it's ever rounded or aligned
	// within the kernel.
	if hostDevice.Headroom < cfg.DeviceHeadroom || hostDevice.Tailroom < cfg.DeviceTailroom {
		logger.Warn("unexpected buffer margins on host link",
			logfields.Device, cfg.HostIfName,
			logfields.DeviceHeadroom, hostDevice.Headroom,
			logfields.DeviceTailroom, hostDevice.Tailroom)
	}
	if peerDevice.Headroom != hostDevice.Headroom || peerDevice.Tailroom != hostDevice.Tailroom {
		return nil, fmt.Errorf("mismatched buffer margins on peer link %s (%s:%d %s:%d)",
			cfg.PeerIfName,
			logfields.DeviceHeadroom, peerDevice.Headroom,
			logfields.DeviceTailroom, peerDevice.Tailroom)
	}

	return peerLink, nil
}
