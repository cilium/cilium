package common

import (
	"fmt"
	"net"
	"os"
	"syscall"

	l "github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/op/go-logging"
	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/vishvananda/netlink"
)

var (
	DebugEnabled bool = false
)

// goArray2C transforms a byte slice into its hexadecimal string representation.
// Example:
// array := []byte{0x12, 0xFF, 0x0, 0x01}
// fmt.Print(GoArray2C(array)) // "{ 0x12, 0xff, 0x0, 0x1 }"
func goArray2C(array []byte) string {
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

// FmtDefineAddress returns the a define string from the given name and addr.
// Example:
// fmt.Print(FmtDefineAddress("foo", []byte{1, 2, 3})) // "#define foo { .addr = { 0x1, 0x2, 0x3 } }\n"
func FmtDefineAddress(name string, addr []byte) string {
	return fmt.Sprintf("#define %s { .addr = %s }\n", name, goArray2C(addr))
}

// FmtDefineArray returns the a define string from the given name and array.
// Example:
// fmt.Print(FmtDefineArray("foo", []byte{1, 2, 3})) // "#define foo { 0x1, 0x2, 0x3 }\n"
func FmtDefineArray(name string, array []byte) string {
	return fmt.Sprintf("#define %s %s\n", name, goArray2C(array))
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

// GenerateV6Prefix generates an IPv6 address created based on the first global IPv4
// address found in the host.
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

// GenerateV4Range generates an IPv4 range from the first global IPv4 address found in the
// host.
func GenerateV4Range() (string, error) {
	ip, err := firstGlobalV4Addr()
	if err != nil {
		return "", err
	}

	return fmtV4Range(&ip)
}

// Swab16 swaps the endianness of n.
func Swab16(n uint16) uint16 {
	return (n&0xFF00)>>8 | (n&0x00FF)<<8
}

// Swab32 swaps the endianness of n.
func Swab32(n uint32) uint32 {
	return ((n & 0x000000ff) << 24) | ((n & 0x0000ff00) << 8) |
		((n & 0x00ff0000) >> 8) | ((n & 0xff000000) >> 24)
}

// GetLockPath returns the lock path representation of the given path.
func GetLockPath(path string) string {
	return path + ".lock"
}

// SetupLOG sets up logger with the correct parameters for the whole cilium architecture.
func SetupLOG(logger *l.Logger, logLevel, hostname string) {
	if logLevel == "DEBUG" {
		DebugEnabled = true
	}

	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	fileFormat := l.MustStringFormatter(
		`%{time:` + RFC3339Milli + `} ` + hostname +
			` %{level:.4s} %{id:03x} %{shortfunc} > %{message}`,
	)

	level, err := l.LogLevel(logLevel)
	if err != nil {
		logger.Fatal(err)
	}

	backend := l.NewLogBackend(os.Stderr, "", 0)
	oBF := l.NewBackendFormatter(backend, fileFormat)

	backendLeveled := l.SetBackend(oBF)
	backendLeveled.SetLevel(level, "")
	logger.SetBackend(backendLeveled)
}
