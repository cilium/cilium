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
	"unsafe"

	"github.com/osrg/gobgp/v3/pkg/log"
)

const (
	tcpMD5SIG       = 14 // TCP MD5 Signature (RFC2385)
	ipv6MinHopCount = 73 // Generalized TTL Security Mechanism (RFC5082)
)

type tcpmd5sig struct {
	ss_family uint16
	ss        [126]byte
	// padding the struct
	_      uint16
	keylen uint16
	// padding the struct
	_   uint32
	key [80]byte
}

func buildTcpMD5Sig(address, key string) (tcpmd5sig, error) {
	t := tcpmd5sig{}
	addr := net.ParseIP(address)
	if addr.To4() != nil {
		t.ss_family = syscall.AF_INET
		copy(t.ss[2:], addr.To4())
	} else {
		t.ss_family = syscall.AF_INET6
		copy(t.ss[6:], addr.To16())
	}

	t.keylen = uint16(len(key))
	copy(t.key[0:], []byte(key))

	return t, nil
}

func setTCPMD5SigSockopt(l *net.TCPListener, address string, key string) error {
	t, err := buildTcpMD5Sig(address, key)
	if err != nil {
		return err
	}
	b := *(*[unsafe.Sizeof(t)]byte)(unsafe.Pointer(&t))

	sc, err := l.SyscallConn()
	if err != nil {
		return err
	}
	return setsockOptString(sc, syscall.IPPROTO_TCP, tcpMD5SIG, string(b[:]))
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
		t, err := buildTcpMD5Sig(addr, password)
		if err != nil {
			return err
		}
		b := *(*[unsafe.Sizeof(t)]byte)(unsafe.Pointer(&t))
		if err := c.Control(func(fd uintptr) {
			sockerr = os.NewSyscallError("setsockopt", syscall.SetsockoptString(int(fd), syscall.IPPROTO_TCP, tcpMD5SIG, string(b[:])))
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
