package netutil

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/Potterli20/golibs-fork/errors"
)

// IPv4Localhost returns the IPv4 localhost address "127.0.0.1".
func IPv4Localhost() (ip netip.Addr) { return netip.AddrFrom4([4]byte{127, 0, 0, 1}) }

// IPv6Localhost returns the IPv6 localhost address "::1".
func IPv6Localhost() (ip netip.Addr) { return netip.AddrFrom16([16]byte{15: 1}) }

// ZeroPrefix returns an IP subnet with prefix 0 and all bytes of the IP address
// set to 0.  fam must be either [AddrFamilyIPv4] or [AddrFamilyIPv6].
func ZeroPrefix(fam AddrFamily) (n netip.Prefix) {
	switch fam {
	case AddrFamilyIPv4:
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	case AddrFamilyIPv6:
		return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	default:
		panic(badAddrFam("ZeroPrefix", fam))
	}
}

// badAddrFam is a helper that returns an informative error for panics caused by
// bad address-family values.
func badAddrFam(fn string, fam AddrFamily) (err error) {
	return fmt.Errorf("netutil.%s: bad address family %d", fn, fam)
}

// IPToAddr converts a [net.IP] into a [netip.Addr] of the given family and
// returns a meaningful error.  ip should not be nil.  fam must be either
// [AddrFamilyIPv4] or [AddrFamilyIPv6].
//
// See also [IPToAddrNoMapped].
func IPToAddr(ip net.IP, fam AddrFamily) (addr netip.Addr, err error) {
	if ip == nil {
		return netip.Addr{}, errors.Error("nil ip")
	}

	switch fam {
	case AddrFamilyIPv4:
		// Make sure that we use the IPv4 form of the address to make sure that
		// netip.Addr doesn't turn out to be an IPv6 one when it really should
		// be an IPv4 one.
		ip4 := ip.To4()
		if ip4 == nil {
			return netip.Addr{}, fmt.Errorf("bad ipv4 net.IP %v", ip)
		}

		ip = ip4
	case AddrFamilyIPv6:
		// Again, make sure that we use the correct form according to the
		// address family.
		ip = ip.To16()
	default:
		panic(badAddrFam("IPToAddr", fam))
	}

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, fmt.Errorf("bad net.IP value %v", ip)
	}

	return addr, nil
}

// IPToAddrNoMapped is like [IPToAddr] but it detects the address family
// automatically by assuming that every IPv6-mapped IPv4 address is actually an
// IPv4 address.  Do not use IPToAddrNoMapped where this assumption isn't safe.
func IPToAddrNoMapped(ip net.IP) (addr netip.Addr, err error) {
	if ip4 := ip.To4(); ip4 != nil {
		return IPToAddr(ip4, AddrFamilyIPv4)
	}

	return IPToAddr(ip, AddrFamilyIPv6)
}

// IPNetToPrefix is a helper that converts a [*net.IPNet] into a [netip.Prefix].
// subnet should not be nil.  fam must be either [AddrFamilyIPv4] or
// [AddrFamilyIPv6].
//
// See also [IPNetToPrefixNoMapped].
func IPNetToPrefix(subnet *net.IPNet, fam AddrFamily) (p netip.Prefix, err error) {
	if subnet == nil {
		return netip.Prefix{}, errors.Error("nil subnet")
	}

	addr, err := IPToAddr(subnet.IP, fam)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("bad ip for subnet %v: %w", subnet, err)
	}

	ones, _ := subnet.Mask.Size()
	p = netip.PrefixFrom(addr, ones)
	if !p.IsValid() {
		return netip.Prefix{}, fmt.Errorf("bad subnet %v", subnet)
	}

	return p, nil
}

// IPNetToPrefixNoMapped is like [IPNetToPrefix] but it detects the address
// family automatically by assuming that every IPv6-mapped IPv4 address is
// actually an IPv4 address.  Do not use IPNetToPrefixNoMapped where this
// assumption isn't safe.
func IPNetToPrefixNoMapped(subnet *net.IPNet) (p netip.Prefix, err error) {
	if subnet == nil {
		return netip.Prefix{}, errors.Error("nil subnet")
	}

	if ip4 := subnet.IP.To4(); ip4 != nil {
		subnet.IP = ip4

		return IPNetToPrefix(subnet, AddrFamilyIPv4)
	}

	return IPNetToPrefix(subnet, AddrFamilyIPv6)
}

// NetAddrToAddrPort converts a [net.Addr] into a [netip.AddrPort] if it can.
// Otherwise, it returns an empty netip.AddrPort.  addr must not be nil.
//
// Since [net.TCPAddr.AddrPort] and [net.UDPAddr.AddrPort] perform a naïve
// conversion of their [net.IP] values into [netip.Addr] ones, that does not
// take mapped addresses into account, IPv4-mapped IPv6 addresses are assumed to
// actually be IPv4 addresses and are normalized into them.
//
// Those who want a conversion without this normalization may use:
//
//	if ap, ok := addr.(interface{ AddrPort() (a netip.AddrPort) }); ok {
//		return ap.AddrPort()
//	}
//
// See https://github.com/golang/go/issues/53607.
func NetAddrToAddrPort(addr net.Addr) (addrPort netip.AddrPort) {
	if ap, ok := addr.(interface{ AddrPort() (a netip.AddrPort) }); ok {
		addrPort = ap.AddrPort()
		ip := addrPort.Addr()
		if ip.Is4In6() {
			addrPort = netip.AddrPortFrom(ip.Unmap(), addrPort.Port())
		}
	}

	return addrPort
}
