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
//go:build dragonfly || freebsd || netbsd
// +build dragonfly freebsd netbsd

package server

import (
	"net"
	"syscall"
)

const (
	tcpMD5SIG       = 0x10 // TCP MD5 Signature (RFC2385)
	ipv6MinHopCount = 73   // Generalized TTL Security Mechanism (RFC5082)
)

func setTcpMD5SigSockopt(l *net.TCPListener, address string, key string) error {
	sc, err := l.SyscallConn()
	if err != nil {
		return err
	}
	// always enable and assumes that the configuration is done by setkey()
	return setsockOptInt(sc, syscall.IPPROTO_TCP, tcpMD5SIG, 1)
}

func setTcpTTLSockopt(conn *net.TCPConn, ttl int) error {
	family := extractFamilyFromTCPConn(conn)
	sc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	return setsockoptIpTtl(sc, family, ttl)
}

func setTcpMinTTLSockopt(conn *net.TCPConn, ttl int) error {
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
