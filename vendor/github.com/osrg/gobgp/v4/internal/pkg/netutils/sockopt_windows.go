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

package netutils

import (
	"fmt"
	"log/slog"
	"net"
	"syscall"
)

const (
	tcpMD5SIG       = 14   // TCP MD5 Signature (RFC2385)
	ipv6MinHopCount = 73   // Generalized TTL Security Mechanism (RFC5082)
	IP_MINTTL       = 0x15 // pulled from https://golang.org/pkg/syscall/?GOOS=linux#IP_MINTTL
	TCP_MAXSEG      = 0x2  // pulled from https://pkg.go.dev/syscall?GOOS=linux#TCP_MAXSEG
)

func SetTCPMD5SigSockopt(l *net.TCPListener, address string, key string) error {
	return fmt.Errorf("setting md5 is not supported")
}

func SetBindToDevSockopt(sc syscall.RawConn, device string) error {
	return fmt.Errorf("binding connection to a device is not supported")
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
	name := IP_MINTTL
	if family == syscall.AF_INET6 {
		level = syscall.IPPROTO_IPV6
		name = ipv6MinHopCount
	}
	return setSockOptInt(sc, level, name, ttl)
}

func SetTCPMSSSockopt(conn net.Conn, mss uint16) error {
	// TCP_MAXSEG syscall option exists only from Windows 10
	// https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getsockopt
	sc, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		return err
	}
	level := syscall.IPPROTO_TCP
	name := TCP_MAXSEG
	return setSockOptInt(sc, level, name, int(mss))
}

func SetIPTOSSockopt(conn net.Conn, tos uint8) error {
	// MSFT advises "do not use" IP_TOS syscall option
	// https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
	return fmt.Errorf("setting ip tos is not supported")
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

func DialerControl(logger *slog.Logger, network, address string, c syscall.RawConn, ttl, ttlMin uint8, mss uint16, password string, bindInterface string, tos uint8) error {
	if password != "" {
		logger.Warn("setting md5 for active connection is not supported",
			slog.String("Topic", "Peer"),
			slog.String("Key", address))
	}
	if ttl != 0 {
		logger.Warn("setting ttl for active connection is not supported",
			slog.String("Topic", "Peer"),
			slog.String("Key", address))
	}
	if ttlMin != 0 {
		logger.Warn("setting min ttl for active connection is not supported",
			slog.String("Topic", "Peer"),
			slog.String("Key", address))
	}
	if mss != 0 {
		logger.Warn("setting MSS for active connection is not supported",
			slog.String("Topic", "Peer"),
			slog.String("Key", address))
	}
	if tos != 0 {
		logger.Warn("setting TOS for active connection is not supported",
			slog.String("Topic", "Peer"),
			slog.String("Key", address))
	}
	return nil
}
