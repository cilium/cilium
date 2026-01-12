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

// setupVethPair sets up the host-facing interface, the peer interface and fills
// up some endpoint fields such as mac, NodeMac, ifIndex and ifName. Returns a pointer
// for the created veth, a pointer for the peer link and error if something fails.
func setupVethPair(defaultLogger *slog.Logger, cfg types.LinkConfig, sysctl sysctl.Sysctl) (*netlink.Veth, netlink.Link, error) {
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
			Name:         cfg.HostIfName,
			HardwareAddr: net.HardwareAddr(epHostMAC),
			TxQLen:       1000,
		},
		PeerName:         cfg.PeerIfName,
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
		logfields.VethPair, []string{veth.PeerName, cfg.HostIfName},
	)

	// Disable reverse path filter on the host side veth peer to allow
	// container addresses to be used as source address when the linux
	// stack performs routing.
	err = DisableRpFilter(sysctl, cfg.HostIfName)
	if err != nil {
		return nil, nil, err
	}

	peer, err := safenetlink.LinkByName(cfg.PeerIfName)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to lookup veth peer just created: %w", err)
	}

	return veth, peer, nil
}
