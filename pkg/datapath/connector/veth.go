// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import (
	"fmt"
	"net"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
)

// SetupVethRemoteNs renames the netdevice in the target namespace to the
// provided dstIfName.
func SetupVethRemoteNs(netNs ns.NetNS, srcIfName, dstIfName string) error {
	return netNs.Do(func(_ ns.NetNS) error {
		err := link.Rename(srcIfName, dstIfName)
		if err != nil {
			return fmt.Errorf("failed to rename veth from %q to %q: %s", srcIfName, dstIfName, err)
		}
		return nil
	})
}

// SetupVeth sets up the net interface, the temporary interface and fills up some endpoint
// fields such as mac, NodeMac, ifIndex and ifName. Returns a pointer for the created
// veth, a pointer for the temporary link, the name of the temporary link and error if
// something fails.
func SetupVeth(id string, mtu, groIPv6MaxSize, gsoIPv6MaxSize, groIPv4MaxSize, gsoIPv4MaxSize int, ep *models.EndpointChangeRequest) (*netlink.Veth, netlink.Link, string, error) {
	if id == "" {
		return nil, nil, "", fmt.Errorf("invalid: empty ID")
	}

	lxcIfName := Endpoint2IfName(id)
	tmpIfName := Endpoint2TempIfName(id)

	veth, link, err := SetupVethWithNames(lxcIfName, tmpIfName, mtu,
		groIPv6MaxSize, gsoIPv6MaxSize, groIPv4MaxSize, gsoIPv4MaxSize, ep)
	return veth, link, tmpIfName, err
}

// SetupVethWithNames sets up the net interface, the peer interface and fills up some endpoint
// fields such as mac, NodeMac, ifIndex and ifName. Returns a pointer for the created
// veth, a pointer for the peer link and error if something fails.
func SetupVethWithNames(lxcIfName, peerIfName string, mtu, groIPv6MaxSize, gsoIPv6MaxSize, groIPv4MaxSize, gsoIPv4MaxSize int, ep *models.EndpointChangeRequest) (*netlink.Veth, netlink.Link, error) {
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
		return nil, nil, fmt.Errorf("unable to generate rnd mac addr: %s", err)
	}
	epLXCMAC, err := mac.GenerateRandMAC()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate rnd mac addr: %s", err)
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
		return nil, nil, fmt.Errorf("unable to create veth pair: %s", err)
	}
	defer func() {
		if err != nil {
			if err = netlink.LinkDel(veth); err != nil {
				log.WithError(err).WithField(logfields.Veth, veth.Name).Warn("failed to clean up veth")
			}
		}
	}()

	log.WithField(logfields.VethPair, []string{veth.PeerName, lxcIfName}).Debug("Created veth pair")

	// Disable reverse path filter on the host side veth peer to allow
	// container addresses to be used as source address when the linux
	// stack performs routing.
	err = DisableRpFilter(lxcIfName)
	if err != nil {
		return nil, nil, err
	}

	peer, err := netlink.LinkByName(peerIfName)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to lookup veth peer just created: %s", err)
	}

	if err = netlink.LinkSetMTU(peer, mtu); err != nil {
		return nil, nil, fmt.Errorf("unable to set MTU to %q: %s", peerIfName, err)
	}

	hostVeth, err := netlink.LinkByName(lxcIfName)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to lookup veth just created: %s", err)
	}

	if err = netlink.LinkSetMTU(hostVeth, mtu); err != nil {
		return nil, nil, fmt.Errorf("unable to set MTU to %q: %s", lxcIfName, err)
	}

	if err = netlink.LinkSetUp(veth); err != nil {
		return nil, nil, fmt.Errorf("unable to bring up veth pair: %s", err)
	}

	if groIPv6MaxSize > 0 {
		if err = netlink.LinkSetGROMaxSize(hostVeth, groIPv6MaxSize); err != nil {
			return nil, nil, fmt.Errorf("unable to set GRO max size to %q: %w",
				lxcIfName, err)
		}
		if err = netlink.LinkSetGROMaxSize(peer, groIPv6MaxSize); err != nil {
			return nil, nil, fmt.Errorf("unable to set GRO max size to %q: %w",
				peerIfName, err)
		}
	}

	if gsoIPv6MaxSize > 0 {
		if err = netlink.LinkSetGSOMaxSize(hostVeth, gsoIPv6MaxSize); err != nil {
			return nil, nil, fmt.Errorf("unable to set GSO max size to %q: %w",
				lxcIfName, err)
		}
		if err = netlink.LinkSetGSOMaxSize(peer, gsoIPv6MaxSize); err != nil {
			return nil, nil, fmt.Errorf("unable to set GSO max size to %q: %w",
				peerIfName, err)
		}
	}

	if groIPv4MaxSize > 0 {
		if err = netlink.LinkSetGROIPv4MaxSize(hostVeth, groIPv4MaxSize); err != nil {
			return nil, nil, fmt.Errorf("unable to set GRO max size to %q: %w",
				lxcIfName, err)
		}
		if err = netlink.LinkSetGROIPv4MaxSize(peer, groIPv4MaxSize); err != nil {
			return nil, nil, fmt.Errorf("unable to set GRO max size to %q: %w",
				peerIfName, err)
		}
	}

	if gsoIPv4MaxSize > 0 {
		if err = netlink.LinkSetGSOIPv4MaxSize(hostVeth, gsoIPv4MaxSize); err != nil {
			return nil, nil, fmt.Errorf("unable to set GSO max size to %q: %w",
				lxcIfName, err)
		}
		if err = netlink.LinkSetGSOIPv4MaxSize(peer, gsoIPv4MaxSize); err != nil {
			return nil, nil, fmt.Errorf("unable to set GSO max size to %q: %w",
				peerIfName, err)
		}
	}

	ep.Mac = peer.Attrs().HardwareAddr.String()
	ep.HostMac = hostVeth.Attrs().HardwareAddr.String()
	ep.InterfaceIndex = int64(hostVeth.Attrs().Index)
	ep.InterfaceName = lxcIfName

	return veth, peer, nil
}
