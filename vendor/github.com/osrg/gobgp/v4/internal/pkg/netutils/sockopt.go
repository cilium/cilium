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

//go:build !linux && !openbsd && !windows

package netutils

import (
	"fmt"
	"log/slog"
	"net"
	"syscall"
)

func SetTCPMD5SigSockopt(l *net.TCPListener, address string, key string) error {
	return SetTcpMD5SigSockopt(l, address, key)
}

func SetTCPTTLSockopt(conn net.Conn, ttl int) error {
	return SetTcpTTLSockopt(conn, ttl)
}

func SetTCPMinTTLSockopt(conn net.Conn, ttl int) error {
	return SetTcpMinTTLSockopt(conn, ttl)
}

func SetBindToDevSockopt(sc syscall.RawConn, device string) error {
	return fmt.Errorf("binding connection to a device is not supported")
}

func SetTCPMSSSockopt(conn net.Conn, mss uint16) error {
	return SetTcpMSSSockopt(conn, mss)
}

func SetIPTOSSockopt(conn net.Conn, tos uint8) error {
	return SetIpTOSSockopt(conn, tos)
}

func SetUDPTTLSockopt(conn net.Conn, ttl int) error {
	return SetUdpTTLSockopt(conn, ttl)
}

func SetReuseAddrSockopt(sc syscall.RawConn) error {
	return SetReuseAddrSockoptImpl(sc)
}

func DialerControl(logger *slog.Logger, network, address string, c syscall.RawConn, ttl, minTtl uint8, mss uint16, password string, bindInterface string, tos uint8) error {
	if password != "" {
		logger.Warn("setting md5 for active connection is not supported",
			slog.String("Topic", "Peer"),
			slog.String("Key", address),
		)
	}
	if ttl != 0 {
		logger.Warn("setting ttl for active connection is not supported",
			slog.String("Topic", "Peer"),
			slog.String("Key", address),
		)
	}
	if minTtl != 0 {
		logger.Warn("setting min ttl for active connection is not supported",
			slog.String("Topic", "Peer"),
			slog.String("Key", address),
		)
	}
	if mss != 0 {
		logger.Warn("setting MSS for active connection is not supported",
			slog.String("Topic", "Peer"),
			slog.String("Key", address),
		)
	}
	if tos != 0 {
		logger.Warn("setting TOS for active connection is not supported",
			slog.String("Topic", "Peer"),
			slog.String("Key", address),
		)
	}
	return nil
}
