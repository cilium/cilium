// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/netns"
)

// SetupVethRemoteNs renames the netdevice in the target namespace to the
// provided dstIfName.
func SetupVethRemoteNs(ns *netns.NetNS, srcIfName, dstIfName string) error {
	return ns.Do(func() error {
		err := link.Rename(srcIfName, dstIfName)
		if err != nil {
			return fmt.Errorf("failed to rename veth from %q to %q: %w", srcIfName, dstIfName, err)
		}
		return nil
	})
}

// SetupVeth sets up the net interface, the temporary interface and fills up some endpoint
// fields such as mac, NodeMac, ifIndex and ifName. Returns a pointer for the created
// veth, a pointer for the temporary link, the name of the temporary link and error if
// something fails.
func SetupVeth(defaultLogger *slog.Logger, id string, cfg LinkConfig, ep *models.EndpointChangeRequest, sysctl sysctl.Sysctl) (*netlink.Veth, netlink.Link, string, error) {
	if id == "" {
		return nil, nil, "", fmt.Errorf("invalid: empty ID")
	}

	lxcIfName := Endpoint2IfName(id)
	tmpIfName := Endpoint2TempIfName(id)

	veth, link, err := SetupVethWithNames(defaultLogger, lxcIfName, tmpIfName, cfg, ep, sysctl)
	return veth, link, tmpIfName, err
}

// LinkConfig contains the GRO/GSO and MTU values to be configured on both sides of the created pair.
type LinkConfig struct {
	GROIPv6MaxSize int
	GSOIPv6MaxSize int

	GROIPv4MaxSize int
	GSOIPv4MaxSize int

	DeviceMTU int
}

// SetupVethWithNames sets up the net interface, the peer interface and fills up some endpoint
// fields such as mac, NodeMac, ifIndex and ifName. Returns a pointer for the created
// veth, a pointer for the peer link and error if something fails.
func SetupVethWithNames(defaultLogger *slog.Logger, lxcIfName, peerIfName string, cfg LinkConfig, ep *models.EndpointChangeRequest, sysctl sysctl.Sysctl) (*netlink.Veth, netlink.Link, error) {
	logger := defaultLogger.With(logfields.LogSubsys, "endpoint-connector")
	// systemd 242+ tries to set a "persistent" MAC addr for any virtual device
	// by default (controlled by MACAddressPolicy). As setting happens
	// asynchronously after a device has been created, ep.Mac and ep.HostMac
	// can become stale which has a serious consequence - the kernel will drop
	// any packet sent to/from the endpoint. However, we can trick systemd by
	// explicitly setting MAC addrs for both veth ends. This sets
	// addr_assign_type for NET_ADDR_SET which prevents systemd from changing
	// the addrs.
	epHostMAC, err := mac.GenerateRandMAC()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate rnd mac addr: %w", err)
	}
	epLXCMAC, err := mac.GenerateRandMAC()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate rnd mac addr: %w", err)
	}

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:         lxcIfName,
			HardwareAddr: net.HardwareAddr(epHostMAC),
			TxQLen:       1000,
		},
		PeerName:         peerIfName,
		PeerHardwareAddr: net.HardwareAddr(epLXCMAC),
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return nil, nil, fmt.Errorf("unable to create veth pair: %w", err)
	}
	defer func() {
		if err != nil {
			if err = netlink.LinkDel(veth); err != nil {
				logger.Warn("failed to clean up veth",
					logfields.Error, err,
					logfields.Veth, veth.Name,
				)
			}
		}
	}()

	logger.Debug("Created veth pair",
		logfields.VethPair, []string{veth.PeerName, lxcIfName},
	)

	// Disable reverse path filter on the host side veth peer to allow
	// container addresses to be used as source address when the linux
	// stack performs routing.
	err = DisableRpFilter(sysctl, lxcIfName)
	if err != nil {
		return nil, nil, err
	}

	peer, err := safenetlink.LinkByName(peerIfName)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to lookup veth peer just created: %w", err)
	}

	err = configurePair(veth, peer, cfg)
	if err != nil {
		return nil, nil, err
	}

	ep.Mac = peer.Attrs().HardwareAddr.String()
	ep.HostMac = veth.Attrs().HardwareAddr.String()
	ep.InterfaceIndex = int64(veth.Attrs().Index)
	ep.InterfaceName = lxcIfName

	return veth, peer, nil
}

func configurePair(hostSide, endpointSide netlink.Link, cfg LinkConfig) error {
	var err error
	epIfName := endpointSide.Attrs().Name
	hostIfName := hostSide.Attrs().Name

	if err = netlink.LinkSetMTU(hostSide, cfg.DeviceMTU); err != nil {
		return fmt.Errorf("unable to set MTU to %q: %w", hostIfName, err)
	}

	if err = netlink.LinkSetMTU(endpointSide, cfg.DeviceMTU); err != nil {
		return fmt.Errorf("unable to set MTU to %q: %w", epIfName, err)
	}

	if err = netlink.LinkSetUp(hostSide); err != nil {
		return fmt.Errorf("unable to bring up %q: %w", hostIfName, err)
	}

	if cfg.GROIPv6MaxSize > 0 {
		if err = netlink.LinkSetGROMaxSize(hostSide, cfg.GROIPv6MaxSize); err != nil {
			return fmt.Errorf("unable to set GRO max size to %q: %w",
				hostIfName, err)
		}
		if err = netlink.LinkSetGROMaxSize(endpointSide, cfg.GROIPv6MaxSize); err != nil {
			return fmt.Errorf("unable to set GRO max size to %q: %w",
				epIfName, err)
		}
	}

	if cfg.GSOIPv6MaxSize > 0 {
		if err = netlink.LinkSetGSOMaxSize(hostSide, cfg.GSOIPv6MaxSize); err != nil {
			return fmt.Errorf("unable to set GSO max size to %q: %w",
				hostIfName, err)
		}
		if err = netlink.LinkSetGSOMaxSize(endpointSide, cfg.GSOIPv6MaxSize); err != nil {
			return fmt.Errorf("unable to set GSO max size to %q: %w",
				epIfName, err)
		}
	}

	if cfg.GROIPv4MaxSize > 0 {
		if err = netlink.LinkSetGROIPv4MaxSize(hostSide, cfg.GROIPv4MaxSize); err != nil {
			return fmt.Errorf("unable to set GRO max size to %q: %w",
				hostIfName, err)
		}
		if err = netlink.LinkSetGROIPv4MaxSize(endpointSide, cfg.GROIPv4MaxSize); err != nil {
			return fmt.Errorf("unable to set GRO max size to %q: %w",
				epIfName, err)
		}
	}

	if cfg.GSOIPv4MaxSize > 0 {
		if err = netlink.LinkSetGSOIPv4MaxSize(hostSide, cfg.GSOIPv4MaxSize); err != nil {
			return fmt.Errorf("unable to set GSO max size to %q: %w",
				hostIfName, err)
		}
		if err = netlink.LinkSetGSOIPv4MaxSize(endpointSide, cfg.GSOIPv4MaxSize); err != nil {
			return fmt.Errorf("unable to set GSO max size to %q: %w",
				epIfName, err)
		}
	}
	return nil
}
