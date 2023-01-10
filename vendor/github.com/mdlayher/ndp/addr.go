package ndp

import (
	"fmt"
	"net"
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
func chooseAddr(addrs []net.Addr, zone string, addr Addr) (*net.IPAddr, error) {
	// Does the caller want an unspecified address?
	if addr == Unspecified {
		return &net.IPAddr{
			IP:   net.IPv6unspecified,
			Zone: zone,
		}, nil
	}

	// Select an IPv6 address from the interface's addresses.
	var match func(ip net.IP) bool
	switch addr {
	case LinkLocal:
		match = linkLocalUnicastAddr
	case UniqueLocal:
		match = uniqueLocalUnicastAddr
	case Global:
		match = globalUnicastAddr
	default:
		// Special case: try to match Addr as a literal IPv6 address.
		ip := net.ParseIP(string(addr))
		if ip == nil {
			return nil, fmt.Errorf("ndp: invalid IPv6 address: %q", addr)
		}

		if err := checkIPv6(ip); err != nil {
			return nil, err
		}

		match = func(check net.IP) bool {
			return ip.Equal(check)
		}
	}

	return findAddr(addrs, addr, zone, match)
}

// findAddr searches for a valid IPv6 address in the slice of net.Addr that
// matches the input function.  If none is found, the IPv6 unspecified address
// "::" is returned.
func findAddr(addrs []net.Addr, addr Addr, zone string, match func(ip net.IP) bool) (*net.IPAddr, error) {
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}

		if err := checkIPv6(ipn.IP); err != nil {
			continue
		}

		// From here on, we can assume that only IPv6 addresses are
		// being checked.
		if match(ipn.IP) {
			return &net.IPAddr{
				IP:   ipn.IP,
				Zone: zone,
			}, nil
		}
	}

	// No matching address on this interface.
	return nil, fmt.Errorf("ndp: address %q not found on interface %q", addr, zone)
}

// linkLocalUnicastAddr matches link-local unicast addresses.
func linkLocalUnicastAddr(ip net.IP) bool {
	return ip.IsLinkLocalUnicast()
}

// ula is the prefix for unique local unicast addresses.
var ula = func() *net.IPNet {
	_, p, err := net.ParseCIDR("fc00::/7")
	if err != nil {
		panic(fmt.Sprintf("failed to parse unique local address prefix: %v", err))
	}

	return p
}()

// uniqueLocalUnicastAddr matches unique local unicast addresses.
func uniqueLocalUnicastAddr(ip net.IP) bool {
	return ula.Contains(ip)
}

// globalUnicastAddr matches global unicast addresses.
func globalUnicastAddr(ip net.IP) bool {
	// Note that IsGlobalUnicast also matches ULAs, so we must exclude
	// them specifically.
	return !ula.Contains(ip) && ip.IsGlobalUnicast()
}
