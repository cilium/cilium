//go:build freebsd
// +build freebsd

package wgfreebsd

// #include <stdlib.h>
// #include <netinet/in.h>
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wgfreebsd/internal/nv"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wgfreebsd/internal/wgh"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wginternal"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ifGroupWG is the WireGuard interface group name passed to the kernel.
var ifGroupWG = [16]byte{0: 'w', 1: 'g'}

var _ wginternal.Client = &Client{}

// A Client provides access to FreeBSD WireGuard ioctl information.
type Client struct {
	// Hooks which use system calls by default, but can also be swapped out
	// during tests.
	close           func() error
	ioctlIfgroupreq func(*wgh.Ifgroupreq) error
	ioctlWGDataIO   func(uint, *wgh.WGDataIO) error
}

// New creates a new Client and returns whether or not the ioctl interface
// is available.
func New() (*Client, bool, error) {
	// The FreeBSD ioctl interface operates on a generic AF_INET socket.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, false, err
	}

	// TODO(mdlayher): find a call to invoke here to probe for availability.
	// c.Devices won't work because it returns a "not found" error when the
	// kernel WireGuard implementation is available but the interface group
	// has no members.

	// By default, use system call implementations for all hook functions.
	return &Client{
		close:           func() error { return unix.Close(fd) },
		ioctlIfgroupreq: ioctlIfgroupreq(fd),
		ioctlWGDataIO:   ioctlWGDataIO(fd),
	}, true, nil
}

// Close implements wginternal.Client.
func (c *Client) Close() error {
	return c.close()
}

// Devices implements wginternal.Client.
func (c *Client) Devices() ([]*wgtypes.Device, error) {
	ifg := wgh.Ifgroupreq{
		// Query for devices in the "wg" group.
		Name: ifGroupWG,
	}

	// Determine how many device names we must allocate memory for.
	if err := c.ioctlIfgroupreq(&ifg); err != nil {
		return nil, err
	}

	// ifg.Len is size in bytes; allocate enough memory for the correct number
	// of wgh.Ifgreq and then store a pointer to the memory where the data
	// should be written (ifgrs) in ifg.Groups.
	//
	// From a thread in golang-nuts, this pattern is valid:
	// "It would be OK to pass a pointer to a struct to ioctl if the struct
	// contains a pointer to other Go memory, but the struct field must have
	// pointer type."
	// See: https://groups.google.com/forum/#!topic/golang-nuts/FfasFTZvU_o.
	ifgrs := make([]wgh.Ifgreq, ifg.Len/wgh.SizeofIfgreq)
	ifg.Groups = &ifgrs[0]

	// Now actually fetch the device names.
	if err := c.ioctlIfgroupreq(&ifg); err != nil {
		return nil, err
	}

	// Keep this alive until we're done doing the ioctl dance.
	runtime.KeepAlive(&ifg)

	devices := make([]*wgtypes.Device, 0, len(ifgrs))
	for _, ifgr := range ifgrs {
		// Remove any trailing NULL bytes from the interface names.
		name := string(bytes.TrimRight(ifgr.Ifgrqu[:], "\x00"))

		device, err := c.Device(name)
		if err != nil {
			return nil, err
		}

		devices = append(devices, device)
	}

	return devices, nil
}

// Device implements wginternal.Client.
func (c *Client) Device(name string) (*wgtypes.Device, error) {
	dname, err := deviceName(name)
	if err != nil {
		return nil, err
	}

	// First, specify the name of the device and determine how much memory
	// must be allocated.
	data := wgh.WGDataIO{
		Name: dname,
	}

	var mem []byte
	for {
		if err := c.ioctlWGDataIO(wgh.SIOCGWG, &data); err != nil {
			// ioctl functions always return a wrapped unix.Errno value.
			// Conform to the wgctrl contract by unwrapping some values:
			//   ENXIO: "no such device": (no such WireGuard device)
			//   EINVAL: "inappropriate ioctl for device" (device is not a
			//	   WireGuard device)
			switch err.(*os.SyscallError).Err {
			case unix.ENXIO, unix.EINVAL:
				return nil, os.ErrNotExist
			default:
				return nil, err
			}
		}

		if len(mem) >= int(data.Size) {
			// Allocated enough memory!
			break
		}

		// Allocate the appropriate amount of memory and point the kernel at
		// the first byte of our slice's backing array. When the loop continues,
		// we will check if we've allocated enough memory.
		mem = make([]byte, data.Size)
		data.Data = &mem[0]
	}

	dev, err := parseDevice(mem)
	if err != nil {
		return nil, err
	}

	dev.Name = name

	return dev, nil
}

// ConfigureDevice implements wginternal.Client.
func (c *Client) ConfigureDevice(name string, cfg wgtypes.Config) error {
	// Check if there is a peer with the UpdateOnly flag set.
	// This is not supported on FreeBSD yet. So error out..
	// TODO(stv0g): remove this check once kernel support has landed.
	for _, peer := range cfg.Peers {
		if peer.UpdateOnly {
			// Check that this device is really an existing kernel
			// device
			if _, err := c.Device(name); err != os.ErrNotExist {
				return wgtypes.ErrUpdateOnlyNotSupported
			}
		}
	}

	m := unparseConfig(cfg)
	mem, sz, err := nv.Marshal(m)
	if err != nil {
		return err
	}
	defer C.free(unsafe.Pointer(mem))

	dname, err := deviceName(name)
	if err != nil {
		return err
	}

	data := wgh.WGDataIO{
		Name: dname,
		Data: mem,
		Size: uint64(sz),
	}

	if err := c.ioctlWGDataIO(wgh.SIOCSWG, &data); err != nil {
		// ioctl functions always return a wrapped unix.Errno value.
		// Conform to the wgctrl contract by unwrapping some values:
		//   ENXIO: "no such device": (no such WireGuard device)
		//   EINVAL: "inappropriate ioctl for device" (device is not a
		//	   WireGuard device)
		switch err.(*os.SyscallError).Err {
		case unix.ENXIO, unix.EINVAL:
			return os.ErrNotExist
		default:
			return err
		}
	}

	return nil
}

// deviceName converts an interface name string to the format required to pass
// with wgh.WGGetServ.
func deviceName(name string) ([16]byte, error) {
	var out [unix.IFNAMSIZ]byte
	if len(name) > unix.IFNAMSIZ {
		return out, fmt.Errorf("wgfreebsd: interface name %q too long", name)
	}

	copy(out[:], name)
	return out, nil
}

// ioctlIfgroupreq returns a function which performs the appropriate ioctl on
// fd to retrieve members of an interface group.
func ioctlIfgroupreq(fd int) func(*wgh.Ifgroupreq) error {
	return func(ifg *wgh.Ifgroupreq) error {
		return ioctl(fd, unix.SIOCGIFGMEMB, unsafe.Pointer(ifg))
	}
}

// ioctlWGDataIO returns a function which performs the appropriate ioctl on
// fd to issue a WireGuard data I/O.
func ioctlWGDataIO(fd int) func(uint, *wgh.WGDataIO) error {
	return func(req uint, data *wgh.WGDataIO) error {
		return ioctl(fd, req, unsafe.Pointer(data))
	}
}

// ioctl is a raw wrapper for the ioctl system call.
func ioctl(fd int, req uint, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}

	return nil
}

func panicf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}

func ntohs(i uint16) int {
	b := *(*[2]byte)(unsafe.Pointer(&i))
	return int(binary.BigEndian.Uint16(b[:]))
}

func htons(i int) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(i))
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

// parseEndpoint converts a struct sockaddr to a Go net.UDPAddr
func parseEndpoint(ep []byte) *net.UDPAddr {
	sa := (*unix.RawSockaddr)(unsafe.Pointer(&ep[0]))

	switch sa.Family {
	case unix.AF_INET:
		sa := (*unix.RawSockaddrInet4)(unsafe.Pointer(&ep[0]))

		ep := &net.UDPAddr{
			IP:   make(net.IP, net.IPv4len),
			Port: ntohs(sa.Port),
		}
		copy(ep.IP, sa.Addr[:])

		return ep
	case unix.AF_INET6:
		sa := (*unix.RawSockaddrInet6)(unsafe.Pointer(&ep[0]))

		// TODO(mdlayher): IPv6 zone?
		ep := &net.UDPAddr{
			IP:   make(net.IP, net.IPv6len),
			Port: ntohs(sa.Port),
		}
		copy(ep.IP, sa.Addr[:])

		return ep
	default:
		// No endpoint configured.
		return nil
	}
}

func unparseEndpoint(ep net.UDPAddr) []byte {
	var b []byte

	if v4 := ep.IP.To4(); v4 != nil {
		b = make([]byte, unsafe.Sizeof(unix.RawSockaddrInet4{}))
		sa := (*unix.RawSockaddrInet4)(unsafe.Pointer(&b[0]))

		sa.Family = unix.AF_INET
		sa.Port = htons(ep.Port)
		copy(sa.Addr[:], v4)
	} else if v6 := ep.IP.To16(); v6 != nil {
		b = make([]byte, unsafe.Sizeof(unix.RawSockaddrInet6{}))
		sa := (*unix.RawSockaddrInet6)(unsafe.Pointer(&b[0]))

		sa.Family = unix.AF_INET6
		sa.Port = htons(ep.Port)
		copy(sa.Addr[:], v6)
	}

	return b
}

// parseAllowedIP unpacks a net.IPNet from a WGAIP structure.
func parseAllowedIP(aip nv.List) net.IPNet {
	cidr := int(aip["cidr"].(uint64))
	if ip, ok := aip["ipv4"]; ok {
		return net.IPNet{
			IP:   net.IP(ip.([]byte)),
			Mask: net.CIDRMask(cidr, 32),
		}
	} else if ip, ok := aip["ipv6"]; ok {
		return net.IPNet{
			IP:   net.IP(ip.([]byte)),
			Mask: net.CIDRMask(cidr, 128),
		}
	} else {
		panicf("wgfreebsd: invalid address family for allowed IP: %+v", aip)
		return net.IPNet{}
	}
}

func unparseAllowedIP(aip net.IPNet) nv.List {
	m := nv.List{}

	ones, _ := aip.Mask.Size()
	m["cidr"] = uint64(ones)

	if v4 := aip.IP.To4(); v4 != nil {
		m["ipv4"] = []byte(v4)
	} else if v6 := aip.IP.To16(); v6 != nil {
		m["ipv6"] = []byte(v6)
	}

	return m
}

// parseTimestamp parses a binary timestamp to a Go time.Time
func parseTimestamp(b []byte) time.Time {
	var secs, nsecs int64

	buf := bytes.NewReader(b)

	// TODO(stv0g): Handle non-little endian machines
	binary.Read(buf, binary.LittleEndian, &secs)
	binary.Read(buf, binary.LittleEndian, &nsecs)

	if secs == 0 && nsecs == 0 {
		return time.Time{}
	}

	return time.Unix(secs, nsecs)
}

// parsePeer unpacks a wgtypes.Peer from a name-value list (nvlist).
func parsePeer(v nv.List) wgtypes.Peer {
	p := wgtypes.Peer{
		ProtocolVersion: 1,
	}

	if v, ok := v["public-key"]; ok {
		pk := (*wgtypes.Key)(v.([]byte))
		p.PublicKey = *pk
	}

	if v, ok := v["preshared-key"]; ok {
		psk := (*wgtypes.Key)(v.([]byte))
		p.PresharedKey = *psk
	}

	if v, ok := v["last-handshake-time"]; ok {
		p.LastHandshakeTime = parseTimestamp(v.([]byte))
	}

	if v, ok := v["endpoint"]; ok {
		p.Endpoint = parseEndpoint(v.([]byte))
	}

	if v, ok := v["persistent-keepalive-interval"]; ok {
		p.PersistentKeepaliveInterval = time.Second * time.Duration(v.(uint64))
	}

	if v, ok := v["rx-bytes"]; ok {
		p.ReceiveBytes = int64(v.(uint64))
	}

	if v, ok := v["tx-bytes"]; ok {
		p.TransmitBytes = int64(v.(uint64))
	}

	if v, ok := v["allowed-ips"]; ok {
		m := v.([]nv.List)
		for _, aip := range m {
			p.AllowedIPs = append(p.AllowedIPs, parseAllowedIP(aip))
		}
	}

	return p
}

// parseDevice decodes the device from a FreeBSD name-value list (nvlist)
func parseDevice(data []byte) (*wgtypes.Device, error) {
	dev := &wgtypes.Device{
		Type: wgtypes.FreeBSDKernel,
	}

	m := nv.List{}
	if err := nv.Unmarshal(data, m); err != nil {
		return nil, err
	}

	if v, ok := m["public-key"]; ok {
		pk := (*wgtypes.Key)(v.([]byte))
		dev.PublicKey = *pk
	}

	if v, ok := m["private-key"]; ok {
		sk := (*wgtypes.Key)(v.([]byte))
		dev.PrivateKey = *sk
	}

	if v, ok := m["user-cookie"]; ok {
		dev.FirewallMark = int(v.(uint64))
	}

	if v, ok := m["listen-port"]; ok {
		dev.ListenPort = int(v.(uint64))
	}

	if v, ok := m["peers"]; ok {
		m := v.([]nv.List)
		for _, n := range m {
			peer := parsePeer(n)
			dev.Peers = append(dev.Peers, peer)
		}
	}

	return dev, nil
}

// unparsePeerConfig encodes a PeerConfig to a name-value list (nvlist).
func unparsePeerConfig(cfg wgtypes.PeerConfig) nv.List {
	m := nv.List{}

	m["public-key"] = cfg.PublicKey[:]

	if v := cfg.PresharedKey; v != nil {
		m["preshared-key"] = v[:]
	}

	if v := cfg.PersistentKeepaliveInterval; v != nil {
		m["persistent-keepalive-interval"] = uint64(v.Seconds())
	}

	if v := cfg.Endpoint; v != nil {
		m["endpoint"] = unparseEndpoint(*v)
	}

	if cfg.ReplaceAllowedIPs {
		m["replace-allowedips"] = true
	}

	if cfg.Remove {
		m["remove"] = true
	}

	if cfg.AllowedIPs != nil {
		aips := []nv.List{}

		for _, aip := range cfg.AllowedIPs {
			aips = append(aips, unparseAllowedIP(aip))
		}

		m["allowed-ips"] = aips
	}

	return m
}

// unparseDevice encodes the device configuration as a FreeBSD name-value list (nvlist).
func unparseConfig(cfg wgtypes.Config) nv.List {
	m := nv.List{}

	if v := cfg.PrivateKey; v != nil {
		m["private-key"] = v[:]
	}

	if v := cfg.ListenPort; v != nil {
		m["listen-port"] = uint64(*v)
	}

	if v := cfg.FirewallMark; v != nil {
		m["user-cookie"] = uint64(*v)
	}

	if cfg.ReplacePeers {
		m["replace-peers"] = true
	}

	if v := cfg.Peers; v != nil {
		peers := []nv.List{}

		for _, p := range v {
			peer := unparsePeerConfig(p)
			peers = append(peers, peer)
		}

		m["peers"] = peers
	}

	return m
}
