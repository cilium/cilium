package common

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	l "github.com/op/go-logging"
	"github.com/vishvananda/netlink"
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

func firstGlobalV4Addr(intf string) (net.IP, error) {
	var link netlink.Link
	var err error

	if intf != "" && intf != "undefined" {
		link, err = netlink.LinkByName(intf)
		if err != nil {
			return firstGlobalV4Addr("")
		}
	}

	addr, err := netlink.AddrList(link, netlink.FAMILY_V4)
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
func GenerateV6Prefix(intf string) (string, error) {
	ip, err := firstGlobalV4Addr(intf)
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
func GenerateV4Range(intf string) (string, error) {
	ip, err := firstGlobalV4Addr(intf)
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
func SetupLOG(logger *l.Logger, logLevel string) {
	hostname, _ := os.Hostname()
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

// GetGroupIDByName returns the group ID for the given grpName.
func GetGroupIDByName(grpName string) (int, error) {
	f, err := os.Open(GroupFilePath)
	if err != nil {
		return -1, err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	for {
		s, err := br.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return -1, err
		}
		p := strings.Split(s, ":")
		if len(p) >= 3 && p[0] == grpName {
			return strconv.Atoi(p[2])
		}
	}
	return -1, fmt.Errorf("group %q not found", grpName)
}

// FindEPConfigCHeader returns the full path of the file that is the CHeaderFileName from
// the slice of files
func FindEPConfigCHeader(basePath string, epFiles []os.FileInfo) string {
	for _, epFile := range epFiles {
		if epFile.Name() == CHeaderFileName {
			return filepath.Join(basePath, epFile.Name())
		}
	}
	return ""
}

// GetCiliumVersionString returns the first line containing CiliumCHeaderPrefix.
func GetCiliumVersionString(epCHeaderFilePath string) (string, error) {
	f, err := os.Open(epCHeaderFilePath)
	if err != nil {
		return "", err
	}
	br := bufio.NewReader(f)
	defer f.Close()
	for {
		s, err := br.ReadString('\n')
		if err == io.EOF {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		if strings.Contains(s, CiliumCHeaderPrefix) {
			return s, nil
		}
	}
}

func ParseHost(host string) (string, *net.TCPAddr, error) {
	protoHost := strings.SplitN(host, "://", 2)
	if len(protoHost) != 2 {
		return "", nil, fmt.Errorf("invalid endpoint")
	}
	tcpAddr, err := net.ResolveTCPAddr(protoHost[0], protoHost[1])
	if err == nil && tcpAddr.Port == 0 {
		return "", nil, fmt.Errorf("invalid endpoint")
	}
	return protoHost[0], tcpAddr, err
}
