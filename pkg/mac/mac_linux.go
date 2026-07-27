// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mac

import (
	"errors"
	"net"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
)

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
