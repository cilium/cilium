// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import (
	"fmt"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
)

// SetupNetkitRemoteNs renames the netdevice in the target namespace to the
// provided dstIfName.
func SetupNetkitRemoteNs(ns *netns.NetNS, srcIfName, dstIfName string) error {
	return ns.Do(func() error {
		err := link.Rename(srcIfName, dstIfName)
		if err != nil {
			return fmt.Errorf("failed to rename netkit from %q to %q: %w", srcIfName, dstIfName, err)
		}
		return nil
	})
}

// SetupNetkit sets up the net interface, the temporary interface and fills up some
// endpoint fields such as mac, NodeMac, ifIndex and ifName. Returns a pointer for the
// created netkit, a pointer for the temporary link, the name of the temporary link
// and error if something fails.
func SetupNetkit(id string, mtu, groIPv6MaxSize, gsoIPv6MaxSize, groIPv4MaxSize, gsoIPv4MaxSize int, l2Mode bool, ep *models.EndpointChangeRequest, sysctl sysctl.Sysctl) (*netlink.Netkit, netlink.Link, string, error) {
	if id == "" {
		return nil, nil, "", fmt.Errorf("invalid: empty ID")
	}

	lxcIfName := Endpoint2IfName(id)
	tmpIfName := Endpoint2TempIfName(id)

	netkit, link, err := SetupNetkitWithNames(lxcIfName, tmpIfName, mtu,
		groIPv6MaxSize, gsoIPv6MaxSize, groIPv4MaxSize, gsoIPv4MaxSize, l2Mode, ep, sysctl)
	return netkit, link, tmpIfName, err
}

// SetupNetkitWithNames sets up the net interface, the peer interface and fills up some
// endpoint fields such as mac, NodeMac, ifIndex and ifName. Returns a pointer for the
// created netkit, a pointer for the peer link and error if something fails.
func SetupNetkitWithNames(lxcIfName, peerIfName string, mtu, groIPv6MaxSize, gsoIPv6MaxSize, groIPv4MaxSize, gsoIPv4MaxSize int, l2Mode bool, ep *models.EndpointChangeRequest, sysctl sysctl.Sysctl) (*netlink.Netkit, netlink.Link, error) {
	mode := netlink.NETKIT_MODE_L3
	if l2Mode {
		mode = netlink.NETKIT_MODE_L2
	}
	netkit := &netlink.Netkit{
		LinkAttrs: netlink.LinkAttrs{
			Name:   lxcIfName,
			TxQLen: 1000,
		},
		Mode:       mode,
		Policy:     netlink.NETKIT_POLICY_FORWARD,
		PeerPolicy: netlink.NETKIT_POLICY_BLACKHOLE,
	}
	peerAttr := &netlink.LinkAttrs{
		Name: peerIfName,
	}
	netkit.SetPeerAttrs(peerAttr)

	err := netlink.LinkAdd(netkit)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create netkit pair: %w", err)
	}
	defer func() {
		if err != nil {
			if err = netlink.LinkDel(netkit); err != nil {
				log.WithError(err).WithField(logfields.Netkit, netkit.Name).Warn("failed to clean up netkit")
			}
		}
	}()

	log.WithField(logfields.NetkitPair, []string{peerIfName, lxcIfName}).Debug("Created netkit pair")

	// Disable reverse path filter on the host side netkit peer to allow
	// container addresses to be used as source address when the linux
	// stack performs routing.
	err = DisableRpFilter(sysctl, lxcIfName)
	if err != nil {
		return nil, nil, err
	}

	peer, err := netlink.LinkByName(peerIfName)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to lookup netkit peer just created: %w", err)
	}

	if err = netlink.LinkSetMTU(peer, mtu); err != nil {
		return nil, nil, fmt.Errorf("unable to set MTU to %q: %w", peerIfName, err)
	}

	hostNetkit, err := netlink.LinkByName(lxcIfName)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to lookup netkit just created: %w", err)
	}

	if err = netlink.LinkSetMTU(hostNetkit, mtu); err != nil {
		return nil, nil, fmt.Errorf("unable to set MTU to %q: %w", lxcIfName, err)
	}

	if err = netlink.LinkSetUp(netkit); err != nil {
		return nil, nil, fmt.Errorf("unable to bring up netkit pair: %w", err)
	}

	if groIPv6MaxSize > 0 {
		if err = netlink.LinkSetGROMaxSize(hostNetkit, groIPv6MaxSize); err != nil {
			return nil, nil, fmt.Errorf("unable to set GRO max size to %q: %w",
				lxcIfName, err)
		}
		if err = netlink.LinkSetGROMaxSize(peer, groIPv6MaxSize); err != nil {
			return nil, nil, fmt.Errorf("unable to set GRO max size to %q: %w",
				peerIfName, err)
		}
	}

	if gsoIPv6MaxSize > 0 {
		if err = netlink.LinkSetGSOMaxSize(hostNetkit, gsoIPv6MaxSize); err != nil {
			return nil, nil, fmt.Errorf("unable to set GSO max size to %q: %w",
				lxcIfName, err)
		}
		if err = netlink.LinkSetGSOMaxSize(peer, gsoIPv6MaxSize); err != nil {
			return nil, nil, fmt.Errorf("unable to set GSO max size to %q: %w",
				peerIfName, err)
		}
	}

	if groIPv4MaxSize > 0 {
		if err = netlink.LinkSetGROIPv4MaxSize(hostNetkit, groIPv4MaxSize); err != nil {
			return nil, nil, fmt.Errorf("unable to set GRO max size to %q: %w",
				lxcIfName, err)
		}
		if err = netlink.LinkSetGROIPv4MaxSize(peer, groIPv4MaxSize); err != nil {
			return nil, nil, fmt.Errorf("unable to set GRO max size to %q: %w",
				peerIfName, err)
		}
	}

	if gsoIPv4MaxSize > 0 {
		if err = netlink.LinkSetGSOIPv4MaxSize(hostNetkit, gsoIPv4MaxSize); err != nil {
			return nil, nil, fmt.Errorf("unable to set GSO max size to %q: %w",
				lxcIfName, err)
		}
		if err = netlink.LinkSetGSOIPv4MaxSize(peer, gsoIPv4MaxSize); err != nil {
			return nil, nil, fmt.Errorf("unable to set GSO max size to %q: %w",
				peerIfName, err)
		}
	}

	ep.Mac = peer.Attrs().HardwareAddr.String()
	ep.HostMac = hostNetkit.Attrs().HardwareAddr.String()
	ep.InterfaceIndex = int64(hostNetkit.Attrs().Index)
	ep.InterfaceName = lxcIfName

	return netkit, peer, nil
}
