package common

import (
	"fmt"
	"net"
	"syscall"

	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/vishvananda/netlink"
)

func GoArray2C(array []byte) string {
	ret := "{ "

	for i, e := range array {
		if i == 0 {
			ret = ret + fmt.Sprintf("%#x", e)
		} else {
			ret = ret + fmt.Sprintf(", %#x", e)
		}
	}

	return ret + " }"
}

func FmtDefineAddress(name string, addr []byte) string {
	return fmt.Sprintf("#define %s { .addr = %s }\n", name, GoArray2C(addr))
}

func FmtDefineArray(name string, array []byte) string {
	return fmt.Sprintf("#define %s %s\n", name, GoArray2C(array))
}

func firstGlobalV4Addr() (net.IP, error) {
	addr, err := netlink.AddrList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}

	for _, a := range addr {
		if a.Scope == syscall.RT_SCOPE_UNIVERSE {
			return a.IP, nil
		}
	}

	return nil, fmt.Errorf("No IPv4 address configured")
}

func fmtV6Prefix(prefix string, ip net.IP) string {
	if len(ip) < 4 {
		return "<nil>"
	}

	return fmt.Sprintf("%s%02x%02x:%02x%02x:0", prefix, ip[0], ip[1], ip[2], ip[3])
}

func GenerateV6Prefix() (string, error) {
	ip, err := firstGlobalV4Addr()
	if err != nil {
		return "", err
	}

	return fmtV6Prefix(DefaultIPv6Prefix, ip), nil
}

func fmtV4Range(ip *net.IP) (string, error) {
	return fmt.Sprintf(DefaultIPv4Range, ip.To4()[3]), nil
}

func GenerateV4Range() (string, error) {
	ip, err := firstGlobalV4Addr()
	if err != nil {
		return "", err
	}

	return fmtV4Range(&ip)
}

func Swab16(n uint16) uint16 {
	return (n&0xFF00)>>8 | (n&0x00FF)<<8
}

func Swab32(n uint32) uint32 {
	return ((n & 0x000000ff) << 24) | ((n & 0x0000ff00) << 8) |
		((n & 0x00ff0000) >> 8) | ((n & 0xff000000) >> 24)
}
