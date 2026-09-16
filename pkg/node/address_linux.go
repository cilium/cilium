// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !darwin

package node

import (
	"errors"
	"net"
	"sort"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/ip"
)

// addrCandidates collects the addresses usable as a node IP that were found by
// one stage of the search in firstGlobalAddr.
type addrCandidates struct {
	public       []netlink.Addr
	private      []netlink.Addr
	hasPreferred bool
}

func (c *addrCandidates) add(a netlink.Addr, isPreferredIP bool) {
	if ip.IsPublicAddr(a.IP) {
		c.public = append(c.public, a)
	} else {
		c.private = append(c.private, a)
	}
	// If the IP is the same as the preferredIP, that
	// means that maybe it is restored from node_config.h,
	// so if it is present we prefer this one, even if it
	// is a secondary address.
	if isPreferredIP {
		c.hasPreferred = true
	}
}

func (c *addrCandidates) empty() bool {
	return len(c.public) == 0 && len(c.private) == 0
}

// pick returns the best of the collected addresses, or nil if there are none.
func (c *addrCandidates) pick(preferredIP net.IP) net.IP {
	if len(c.public) != 0 {
		if c.hasPreferred && ip.IsPublicAddr(preferredIP) {
			return preferredIP
		}

		// Just make sure that we always return the same one and not a
		// random one. More info in the issue GH-7637.
		sort.SliceStable(c.public, func(i, j int) bool {
			return c.public[i].LinkIndex < c.public[j].LinkIndex
		})

		return c.public[0].IP
	}

	if len(c.private) != 0 {
		if c.hasPreferred && !ip.IsPublicAddr(preferredIP) {
			return preferredIP
		}

		// Same stable order, see above public.
		sort.SliceStable(c.private, func(i, j int) bool {
			return c.private[i].LinkIndex < c.private[j].LinkIndex
		})

		return c.private[0].IP
	}

	return nil
}

func firstGlobalAddr(intf string, preferredIP net.IP, family int) (net.IP, error) {
	var link netlink.Link
	var ipLen int
	var err error

	ipsToExclude := GetExcludedIPs()
	linkScopeMax := unix.RT_SCOPE_UNIVERSE
	if family == netlink.FAMILY_V4 {
		ipLen = 4
	} else {
		ipLen = 16
	}

	if intf != "" && intf != "undefined" {
		link, err = safenetlink.LinkByName(intf)
		if err != nil {
			link = nil
		} else {
			ipsToExclude = []net.IP{}
		}
	}

	// Deprecated addresses (RFC 4862), as produced by e.g. kube-vip in ARP
	// mode configuring its VIP with preferred_lft 0, must not be used for new
	// communication. Unlike tentative and dadfailed ones they can still carry
	// traffic though, so rather than rejecting them outright and risking a
	// node with no selectable address at all, keep them aside and only fall
	// back to them once every stage of the search below came up empty.
	deprecated := addrCandidates{}

retryInterface:
	addr, err := safenetlink.AddrList(link, family)
	if err != nil {
		return nil, err
	}

retryScope:
	candidates := addrCandidates{}
	// Only the first stage to find deprecated addresses contributes them, so
	// that the fallback observes the same device and scope preference as the
	// search itself rather than ranking every stage's leftovers together.
	keepDeprecated := deprecated.empty()

	for _, a := range addr {
		isPreferredIP := a.IP.Equal(preferredIP)
		if !addrUsableAsNodeIP(a, isPreferredIP, ipsToExclude, linkScopeMax, ipLen) {
			continue
		}

		if a.Flags&unix.IFA_F_DEPRECATED != 0 {
			if keepDeprecated {
				deprecated.add(a, isPreferredIP)
			}
			continue
		}
		candidates.add(a, isPreferredIP)
	}

	if selected := candidates.pick(preferredIP); selected != nil {
		return selected, nil
	}

	// First, if a device is specified, fall back to anything wider
	// than link (site, custom, ...) before trying all devices.
	if linkScopeMax != unix.RT_SCOPE_SITE {
		linkScopeMax = unix.RT_SCOPE_SITE
		goto retryScope
	}

	// Fall back with retry for all interfaces with full scope again
	// (which then goes back to lower scope again for all interfaces
	// before we give up completely).
	if link != nil {
		linkScopeMax = unix.RT_SCOPE_UNIVERSE
		link = nil
		goto retryInterface
	}

	if selected := deprecated.pick(preferredIP); selected != nil {
		return selected, nil
	}

	return nil, errors.New("No address found")
}

func addrUsableAsNodeIP(a netlink.Addr, isPreferredIP bool, ipsToExclude []net.IP, linkScopeMax, ipLen int) bool {
	if a.Scope > linkScopeMax {
		return false
	}
	if ip.ListContainsIP(ipsToExclude, a.IP) {
		return false
	}
	if len(a.IP) < ipLen {
		return false
	}
	if a.Flags&unix.IFA_F_SECONDARY > 0 && !isPreferredIP {
		return false
	}
	if a.Flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED) != 0 {
		return false
	}
	return true
}

// firstGlobalV4Addr returns the first IPv4 global IP of an interface,
// where the IPs are sorted in creation order (oldest to newest).
//
// All secondary IPs, except the preferredIP, are filtered out.
//
// Public IPs are preferred over private ones. When intf is defined only
// IPs belonging to that interface are considered.
//
// If preferredIP is present in the IP list it is returned irrespective of
// the sort order. However, if preferredIP is a private IP, a public IP will
// be returned if it is assigned to the intf
//
// Passing intf and preferredIP will only return preferredIP if it is in
// the IPs that belong to intf.
//
// In all cases, if intf is not found all interfaces are considered.
//
// If a intf-specific global address couldn't be found, we retry to find
// an address with reduced scope (site, custom) on that particular device.
//
// If the latter fails as well, we retry on all interfaces beginning with
// universe scope again (and then falling back to reduced scope).
//
// Deprecated addresses are only considered once none of the above yielded
// an address.
//
// In case none of the above helped, we bail out with error.
func FirstGlobalV4Addr(intf string, preferredIP net.IP) (net.IP, error) {
	return firstGlobalAddr(intf, preferredIP, netlink.FAMILY_V4)
}

// firstGlobalV6Addr returns first IPv6 global IP of an interface, see
// firstGlobalV4Addr for more details.
func FirstGlobalV6Addr(intf string, preferredIP net.IP) (net.IP, error) {
	return firstGlobalAddr(intf, preferredIP, netlink.FAMILY_V6)
}
