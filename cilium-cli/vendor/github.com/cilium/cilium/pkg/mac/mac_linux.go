// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mac

import (
	"errors"
	"net"

	"github.com/vishvananda/netlink"
)

// HasMacAddr returns true if the given network interface has L2 addr.
func HasMacAddr(iface string) bool {
	link, err := netlink.LinkByName(iface)
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
	l, err := netlink.LinkByName(ifName)
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
