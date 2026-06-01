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

// DisableRpFilter relaxes the reverse-path filter on the specified host-side
// endpoint interface so the datapath can use container addresses as source
// when the Linux stack performs routing.
//
// In addition to disabling rp_filter, it enables accept_local. Proxy-redirected
// (stack-TPROXY) packets are marked and routed via the proxy's
// "local default dev lo" table, which makes the kernel treat them as locally
// destined and run fib_validate_source on the *source*. With
// net.ipv4.conf.all.src_valid_mark=1 (set by Cilium), that reverse-path lookup
// also follows the proxy fwmark to the same local table, so the client source
// resolves as "local" and is dropped as a martian source unless accept_local is
// set on the ingress device. Cilium already applies both relaxations together
// on its own devices (see pkg/datapath/loader/netlink.go); applying them here
// extends the same treatment to endpoint veth/netkit peers, which is where
// pod-origin proxy traffic (e.g. egress toFQDNs DNS proxy, L7LB) is validated.
// See https://github.com/cilium/cilium/issues/46260.
func DisableRpFilter(sysctl sysctl.Sysctl, ifName string) error {
	if err := sysctl.Disable([]string{"net", "ipv4", "conf", ifName, "rp_filter"}); err != nil {
		return err
	}
	return sysctl.Enable([]string{"net", "ipv4", "conf", ifName, "accept_local"})
}
