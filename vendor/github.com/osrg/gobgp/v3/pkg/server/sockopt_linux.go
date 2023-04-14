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
// +build linux

package server

import (
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/osrg/gobgp/v3/pkg/log"
)

const (
	ipv6MinHopCount = 73 // Generalized TTL Security Mechanism (RFC5082)
)

func buildTcpMD5Sig(address, key string) *unix.TCPMD5Sig {
	t := unix.TCPMD5Sig{}
	addr := net.ParseIP(address)
	if addr.To4() != nil {
		t.Addr.Family = unix.AF_INET
		copy(t.Addr.Data[2:], addr.To4())
	} else {
		t.Addr.Family = unix.AF_INET6
		copy(t.Addr.Data[6:], addr.To16())
	}

	t.Keylen = uint16(len(key))
	copy(t.Key[0:], []byte(key))

	return &t
}

func setTCPMD5SigSockopt(l *net.TCPListener, address string, key string) error {
	sc, err := l.SyscallConn()
	if err != nil {
		return err
	}

	var sockerr error
	t := buildTcpMD5Sig(address, key)
	if err := sc.Control(func(s uintptr) {
		sockerr = unix.SetsockoptTCPMD5Sig(int(s), unix.IPPROTO_TCP, unix.TCP_MD5SIG, t)
	}); err != nil {
		return err
	}
	return sockerr
}

func setBindToDevSockopt(sc syscall.RawConn, device string) error {
	return setsockOptString(sc, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device)
}

func setTCPTTLSockopt(conn *net.TCPConn, ttl int) error {
	family := extractFamilyFromTCPConn(conn)
	sc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	return setsockoptIpTtl(sc, family, ttl)
}

func setTCPMinTTLSockopt(conn *net.TCPConn, ttl int) error {
	family := extractFamilyFromTCPConn(conn)
	sc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	level := syscall.IPPROTO_IP
	name := syscall.IP_MINTTL
	if family == syscall.AF_INET6 {
		level = syscall.IPPROTO_IPV6
		name = ipv6MinHopCount
	}
	return setsockOptInt(sc, level, name, ttl)
}

func dialerControl(logger log.Logger, network, address string, c syscall.RawConn, ttl, minTtl uint8, password string, bindInterface string) error {
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
			sockerr = os.NewSyscallError("setsockopt", unix.SetsockoptTCPMD5Sig(int(fd), unix.IPPROTO_TCP, unix.TCP_MD5SIG, t))
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
			sockerr = os.NewSyscallError("setsockopt", syscall.SetsockoptInt(int(fd), level, name, int(ttl)))
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
			sockerr = os.NewSyscallError("setsockopt", syscall.SetsockoptInt(int(fd), level, name, int(minTtl)))
		}); err != nil {
			return err
		}
		if sockerr != nil {
			return sockerr
		}
	}
	if bindInterface != "" {
		if err := setBindToDevSockopt(c, bindInterface); err != nil {
			return err
		}
	}
	return nil
}
