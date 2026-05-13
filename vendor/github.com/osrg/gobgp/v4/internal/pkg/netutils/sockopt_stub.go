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

//go:build !linux && !dragonfly && !freebsd && !netbsd && !openbsd && !darwin && !windows

package netutils

import (
	"fmt"
	"net"
	"syscall"
)

func SetTcpMD5SigSockopt(l *net.TCPListener, address string, key string) error {
	return fmt.Errorf("setting md5 is not supported")
}

func SetTcpTTLSockopt(conn net.Conn, ttl int) error {
	return fmt.Errorf("setting ttl is not supported")
}

func SetTcpMinTTLSockopt(conn net.Conn, ttl int) error {
	return fmt.Errorf("setting min ttl is not supported")
}

func SetTcpMSSSockopt(conn net.Conn, mss uint16) error {
	return fmt.Errorf("setting tcp mss is not supported")
}

func SetIpTOSSockopt(conn net.Conn, tos uint8) error {
	return fmt.Errorf("setting ip tos is not supported")
}

func SetUdpTTLSockopt(conn net.Conn, ttl int) error {
	return fmt.Errorf("setting udp ttl is not supported")
}

func SetReuseAddrSockoptImpl(_ syscall.RawConn) error {
	return fmt.Errorf("setting SO_REUSEADDR is not supported")
}
