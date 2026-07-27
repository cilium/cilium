// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import (
	"crypto/sha256"
	"fmt"
	"slices"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
)

const (
	// HostInterfacePrefix is the Host interface prefix.
	HostInterfacePrefix = "lxc"
	// temporaryInterfacePrefix is the temporary interface prefix while setting up libNetwork interface.
	temporaryInterfacePrefix = "tmp"
	// ciliumCNIAltName is the alternative interface name set on the peer (pod-side)
	// end of every veth/netkit pair created by Cilium. Used to identify
	// Cilium-owned interfaces.
	ciliumCNIAltName = "cilium_cni"
)

// IsCiliumManagedLink returns true if the link was created by Cilium, identified
// by the presence of the CniAltName(ifname) altname attribute.
func IsCiliumManagedLink(link netlink.Link) bool {
	return slices.Contains(link.Attrs().AltNames, CniAltName(link.Attrs().Name))
}

// CniAltName returns the altname for this `ifName`
func CniAltName(ifName string) string {
	return fmt.Sprintf("%s:%s", ciliumCNIAltName, ifName)
}

// Endpoint2IfName returns the host interface name for the given endpointID.
func Endpoint2IfName(endpointID string) string {
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(endpointID)))
	// returned string length should be < unix.IFNAMSIZ
	truncateLength := uint(unix.IFNAMSIZ - len(temporaryInterfacePrefix) - 1)
	return HostInterfacePrefix + truncateString(sum, truncateLength)
}

// Endpoint2TempIfName returns the temporary interface name for the given
// endpointID.
func Endpoint2TempIfName(endpointID string) string {
	return temporaryInterfacePrefix + truncateString(endpointID, 5)
}

func truncateString(epID string, maxLen uint) string {
	if maxLen <= uint(len(epID)) {
		return epID[:maxLen]
	}
	return epID
}

// DisableRpFilter tries to disable rpfilter on specified interface
func DisableRpFilter(sysctl sysctl.Sysctl, ifName string) error {
	return sysctl.Disable([]string{"net", "ipv4", "conf", ifName, "rp_filter"})
}
