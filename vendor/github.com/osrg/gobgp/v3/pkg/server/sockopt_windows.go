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
//go:build windows
// +build windows

package server

import (
	"fmt"
	"net"
	"syscall"

	"github.com/osrg/gobgp/v3/pkg/log"
)

const (
	tcpMD5SIG       = 14   // TCP MD5 Signature (RFC2385)
	ipv6MinHopCount = 73   // Generalized TTL Security Mechanism (RFC5082)
	IP_MINTTL       = 0x15 // pulled from https://golang.org/pkg/syscall/?GOOS=linux#IP_MINTTL
	TCP_MAXSEG      = 0x2  // pulled from https://pkg.go.dev/syscall?GOOS=linux#TCP_MAXSEG
)

func setTCPMD5SigSockopt(l *net.TCPListener, address string, key string) error {
	return fmt.Errorf("setting md5 is not supported")
}

func setBindToDevSockopt(sc syscall.RawConn, device string) error {
	return fmt.Errorf("binding connection to a device is not supported")
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
	name := IP_MINTTL
	if family == syscall.AF_INET6 {
		level = syscall.IPPROTO_IPV6
		name = ipv6MinHopCount
	}
	return setsockOptInt(sc, level, name, ttl)
}

func setTCPMSSSockopt(conn *net.TCPConn, mss uint16) error {
	// TCP_MAXSEG syscall option exists only from Windows 10
	// https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getsockopt
	sc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	level := syscall.IPPROTO_TCP
	name := TCP_MAXSEG
	return setsockOptInt(sc, level, name, int(mss))
}

func dialerControl(logger log.Logger, network, address string, c syscall.RawConn, ttl, ttlMin uint8, mss uint16, password string, bindInterface string) error {
	if password != "" {
		logger.Warn("setting md5 for active connection is not supported",
			log.Fields{
				"Topic": "Peer",
				"Key":   address})
	}
	if ttl != 0 {
		logger.Warn("setting ttl for active connection is not supported",
			log.Fields{
				"Topic": "Peer",
				"Key":   address})
	}
	if ttlMin != 0 {
		logger.Warn("setting min ttl for active connection is not supported",
			log.Fields{
				"Topic": "Peer",
				"Key":   address})
	}
	if mss != 0 {
		logger.Warn("setting MSS for active connection is not supported",
			log.Fields{
				"Topic": "Peer",
				"Key":   address})
	}
	return nil
}
