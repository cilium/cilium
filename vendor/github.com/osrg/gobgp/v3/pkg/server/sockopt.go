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
// +build !linux,!openbsd,!windows

package server

import (
	"fmt"
	"net"
	"syscall"

	"github.com/osrg/gobgp/v3/pkg/log"
)

func setTCPMD5SigSockopt(l *net.TCPListener, address string, key string) error {
	return setTcpMD5SigSockopt(l, address, key)
}

func setTCPTTLSockopt(conn *net.TCPConn, ttl int) error {
	return setTcpTTLSockopt(conn, ttl)
}

func setTCPMinTTLSockopt(conn *net.TCPConn, ttl int) error {
	return setTcpMinTTLSockopt(conn, ttl)
}

func setBindToDevSockopt(sc syscall.RawConn, device string) error {
	return fmt.Errorf("binding connection to a device is not supported")
}

func dialerControl(logger log.Logger, network, address string, c syscall.RawConn, ttl, minTtl uint8, password string, bindInterface string) error {
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
	if minTtl != 0 {
		logger.Warn("setting min ttl for active connection is not supported",
			log.Fields{
				"Topic": "Peer",
				"Key":   address})
	}
	return nil
}
