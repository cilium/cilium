// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

func setKeepAlive(c net.Conn) error {
	if tcp, ok := c.(*net.TCPConn); ok {
		if err := tcp.SetKeepAlive(true); err != nil {
			return fmt.Errorf("unable to enable keepalive: %s", err)
		}

		if err := tcp.SetKeepAlivePeriod(time.Duration(5) * time.Minute); err != nil {
			return fmt.Errorf("unable to set keepalive period: %s", err)
		}
	}

	return nil
}

func ciliumDialer(identity int, network, address string) (net.Conn, error) {
	addr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, fmt.Errorf("unable resolve address %s/%s: %s", network, address, err)
	}

	family := syscall.AF_INET
	if addr.IP.To4() == nil {
		family = syscall.AF_INET6
	}

	fd, err := syscall.Socket(family, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to create socket: %s", err)
	}

	f := os.NewFile(uintptr(fd), addr.String())
	defer f.Close()

	c, err := net.FileConn(f)
	if err != nil {
		return nil, fmt.Errorf("unable to create FileConn: %s", err)
	}

	if identity != 0 {
		setSocketMark(c, identity)
	}

	sockAddr, err := ipToSockaddr(family, addr.IP, addr.Port, addr.Zone)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("unable to create sockaddr: %s", err)
	}

	if err := syscall.SetNonblock(fd, false); err != nil {
		c.Close()
		return nil, fmt.Errorf("unable to put socket in blocking mode: %s", err)
	}

	if err := syscall.Connect(fd, sockAddr); err != nil {
		c.Close()
		return nil, fmt.Errorf("unable to connect: %s", err)
	}

	if err := setKeepAlive(c); err != nil {
		c.Close()
		return nil, err
	}

	return c, nil
}
