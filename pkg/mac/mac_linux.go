// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mac

import (
	"errors"
	"net"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
)

// HasMacAddr returns true if the given network interface has L2 addr.
func HasMacAddr(iface string) bool {
	link, err := safenetlink.LinkByName(iface)
	if err != nil {
		return false
	}
	return LinkHasMacAddr(link)
}

// LinkHasMacAddr returns true if the given network interface has L2 addr.
func LinkHasMacAddr(link netlink.Link) bool {
	return len(link.Attrs().HardwareAddr) != 0
}

// ReplaceMacAddressWithLinkName replaces the MAC address of the given link
func ReplaceMacAddressWithLinkName(ifName, macAddress string) error {
	l, err := safenetlink.LinkByName(ifName)
	if err != nil {
		if errors.As(err, &netlink.LinkNotFoundError{}) {
			return nil
		}
		return err
	}
	hw, err := net.ParseMAC(macAddress)
	if err != nil {
		return err
	}
	return netlink.LinkSetHardwareAddr(l, hw)
}
