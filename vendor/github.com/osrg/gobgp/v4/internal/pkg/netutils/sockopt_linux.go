// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package netutils

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	ipv6MinHopCount = 73 // Generalized TTL Security Mechanism (RFC5082)
)

func buildTcpMD5Sig(address, key string) *unix.TCPMD5Sig {
	t := unix.TCPMD5Sig{}

	var addr netip.Addr
	var err error
	if strings.Contains(address, "/") {
		prefix, err := netip.ParsePrefix(address)
		if err != nil {
			return nil
		}
		addr = prefix.Addr()
		t.Prefixlen = uint8(prefix.Bits())
		t.Flags = unix.TCP_MD5SIG_FLAG_PREFIX
	} else {
		addr, err = netip.ParseAddr(address)
		if err != nil {
			return nil
		}
	}

	if addr.Is4() {
		t.Addr.Family = unix.AF_INET
		bits := addr.As4()
		copy(t.Addr.Data[2:], bits[:])
	} else if addr.Is6() {
		t.Addr.Family = unix.AF_INET6
		bits := addr.As16()
		copy(t.Addr.Data[6:], bits[:])
		if addr.IsLinkLocalUnicast() {
			t.Ifindex, err = zoneToID(addr.Zone())
			if err != nil {
				return nil
			}
		}
	} else {
		return nil
	}

	t.Keylen = uint16(len(key))
	copy(t.Key[0:], []byte(key))

	return &t
}

func zoneToID(zone string) (int32, error) {
	if zone == "" {
		return 0, nil
	}

	if id, err := strconv.ParseInt(zone, 10, 32); err == nil {
		return int32(id), nil
	}

	iface, err := net.InterfaceByName(zone)
	if err != nil {
		return 0, fmt.Errorf("interface %q not found: %w", zone, err)
	}
	return int32(iface.Index), nil
}

func SetTCPMD5SigSockopt(l *net.TCPListener, address string, key string) error {
	sc, err := l.SyscallConn()
	if err != nil {
		return err
	}

	var sockerr error
	t := buildTcpMD5Sig(address, key)
	if t == nil {
		return fmt.Errorf("unable to generate TcpMD5Sig from %s", address)
	}
	if err := sc.Control(func(s uintptr) {
		opt := unix.TCP_MD5SIG

		if strings.Contains(address, "/") {
			opt = unix.TCP_MD5SIG_EXT
		}

		sockerr = unix.SetsockoptTCPMD5Sig(int(s), unix.IPPROTO_TCP, opt, t)
	}); err != nil {
		return err
	}
	return sockerr
}

func setSockOptString(sc syscall.RawConn, level int, opt int, str string) error {
	var opterr error
	fn := func(s uintptr) {
		opterr = syscall.SetsockoptString(int(s), level, opt, str)
	}
	err := sc.Control(fn)
	if opterr == nil {
		return err
	}
	return opterr
}

func SetBindToDevSockopt(sc syscall.RawConn, device string) error {
	return setSockOptString(sc, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device)
}

func SetTCPTTLSockopt(conn net.Conn, ttl int) error {
	family := extractFamilyFromConn(conn)
	sc, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		return err
	}
	return setSockOptIpTtl(sc, family, ttl)
}

func SetTCPMinTTLSockopt(conn net.Conn, ttl int) error {
	family := extractFamilyFromConn(conn)
	sc, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		return err
	}
	level := syscall.IPPROTO_IP
	name := syscall.IP_MINTTL
	if family == syscall.AF_INET6 {
		level = syscall.IPPROTO_IPV6
		name = ipv6MinHopCount
	}
	return setSockOptInt(sc, level, name, ttl)
}

func SetTCPMSSSockopt(conn net.Conn, mss uint16) error {
	family := extractFamilyFromConn(conn)
	sc, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		return err
	}
	return setSockOptTcpMss(sc, family, mss)
}

func SetIPTOSSockopt(conn net.Conn, tos uint8) error {
	family := extractFamilyFromConn(conn)
	sc, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		return err
	}
	return setSockOptIpTos(sc, family, tos)
}

func SetUDPTTLSockopt(conn net.Conn, ttl int) error {
	family := extractFamilyFromConn(conn)
	sc, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		return err
	}
	return setSockOptIpTtl(sc, family, ttl)
}

func SetReuseAddrSockopt(sc syscall.RawConn) error {
	return setSockOptInt(sc, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}

func DialerControl(logger *slog.Logger, network, address string, c syscall.RawConn, ttl, minTtl uint8, mss uint16, password string, bindInterface string, tos uint8) error {
	family := syscall.AF_INET
	raddr, _ := net.ResolveTCPAddr("tcp", address)
	if raddr.IP.To4() == nil {
		family = syscall.AF_INET6
	}

	var sockerr error
	if password != "" {
		addr, _, _ := net.SplitHostPort(address)
		t := buildTcpMD5Sig(addr, password)
		if err := c.Control(func(fd uintptr) {
			sockerr = os.NewSyscallError("setSockOpt", unix.SetsockoptTCPMD5Sig(int(fd), unix.IPPROTO_TCP, unix.TCP_MD5SIG, t))
		}); err != nil {
			return err
		}
		if sockerr != nil {
			return sockerr
		}
	}

	if ttl != 0 {
		if err := c.Control(func(fd uintptr) {
			level := syscall.IPPROTO_IP
			name := syscall.IP_TTL
			if family == syscall.AF_INET6 {
				level = syscall.IPPROTO_IPV6
				name = syscall.IPV6_UNICAST_HOPS
			}
			sockerr = os.NewSyscallError("setSockOpt", syscall.SetsockoptInt(int(fd), level, name, int(ttl)))
		}); err != nil {
			return err
		}
		if sockerr != nil {
			return sockerr
		}
	}

	if minTtl != 0 {
		if err := c.Control(func(fd uintptr) {
			level := syscall.IPPROTO_IP
			name := syscall.IP_MINTTL
			if family == syscall.AF_INET6 {
				level = syscall.IPPROTO_IPV6
				name = ipv6MinHopCount
			}
			sockerr = os.NewSyscallError("setSockOpt", syscall.SetsockoptInt(int(fd), level, name, int(minTtl)))
		}); err != nil {
			return err
		}
		if sockerr != nil {
			return sockerr
		}
	}

	if mss != 0 {
		if err := c.Control(func(fd uintptr) {
			level := syscall.IPPROTO_TCP
			name := syscall.TCP_MAXSEG
			sockerr = os.NewSyscallError("setSockOpt", syscall.SetsockoptInt(int(fd), level, name, int(mss)))
		}); err != nil {
			return err
		}
		if sockerr != nil {
			return sockerr
		}
	}

	if bindInterface != "" {
		if err := SetBindToDevSockopt(c, bindInterface); err != nil {
			return err
		}
	}

	if tos != 0 {
		if err := c.Control(func(fd uintptr) {
			level := syscall.IPPROTO_IP
			name := syscall.IP_TOS
			if family == syscall.AF_INET6 {
				level = syscall.IPPROTO_IPV6
				name = syscall.IPV6_TCLASS
			}
			sockerr = os.NewSyscallError("setSockOpt", syscall.SetsockoptInt(int(fd), level, name, int(tos)))
		}); err != nil {
			return err
		}
		if sockerr != nil {
			return sockerr
		}
	}
	return nil
}
