package ndp

import (
	"fmt"
	"net"
	"net/netip"
)

// An Addr is an IPv6 unicast address.
type Addr string

// Possible Addr types for an IPv6 unicast address.
const (
	Unspecified Addr = "unspecified"
	LinkLocal   Addr = "linklocal"
	UniqueLocal Addr = "uniquelocal"
	Global      Addr = "global"
)

// chooseAddr selects an Addr from the interface based on the specified Addr type.
func chooseAddr(addrs []net.Addr, zone string, addr Addr) (netip.Addr, error) {
	// Does the caller want an unspecified address?
	if addr == Unspecified {
		return netip.IPv6Unspecified().WithZone(zone), nil
	}

	// Select an IPv6 address from the interface's addresses.
	var match func(ip netip.Addr) bool
	switch addr {
	case LinkLocal:
		match = (netip.Addr).IsLinkLocalUnicast
	case UniqueLocal:
		match = (netip.Addr).IsPrivate
	case Global:
		match = func(ip netip.Addr) bool {
			// Specifically exclude the ULA range.
			return ip.IsGlobalUnicast() && !ip.IsPrivate()
		}
	default:
		// Special case: try to match Addr as a literal IPv6 address.
		ip, err := netip.ParseAddr(string(addr))
		if err != nil {
			return netip.Addr{}, fmt.Errorf("ndp: invalid IPv6 address: %q", addr)
		}

		if err := checkIPv6(ip); err != nil {
			return netip.Addr{}, err
		}

		match = func(check netip.Addr) bool {
			return ip == check
		}
	}

	return findAddr(addrs, addr, zone, match)
}

// findAddr searches for a valid IPv6 address in the slice of net.Addr that
// matches the input function.  If none is found, the IPv6 unspecified address
// "::" is returned.
func findAddr(addrs []net.Addr, addr Addr, zone string, match func(ip netip.Addr) bool) (netip.Addr, error) {
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			panicf("ndp: failed to convert net.IPNet: %v", ipn.IP)
		}

		if err := checkIPv6(ip); err != nil {
			continue
		}

		// From here on, we can assume that only IPv6 addresses are
		// being checked.
		if match(ip) {
			return ip.WithZone(zone), nil
		}
	}

	// No matching address on this interface.
	return netip.Addr{}, fmt.Errorf("ndp: address %q not found on interface %q", addr, zone)
}
