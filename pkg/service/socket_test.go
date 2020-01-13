// Copyright 2020 Authors of Cilium
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

// +build !privileged_tests

package service

import (
	"net"
	"syscall"

	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
)

type sock struct {
	domain int
	typ    int
	proto  int
}

type bound struct {
	addr net.IP
	port uint16
}

// fakeSocket mocks the socket interface
type fakeSocket struct {
	mutex   lock.Mutex
	sockets map[int]sock
	bound   map[int]bound
	addrs   []net.Addr
}

func newMockSocket() socket {
	return &fakeSocket{
		sockets: map[int]sock{},
		bound:   map[int]bound{},
	}
}

func (f *fakeSocket) Socket(domain, typ, proto int) (fd int, err error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	fd = len(f.sockets)
	f.sockets[fd] = sock{domain, typ, proto}
	return fd, nil
}

func (f *fakeSocket) Bind(fd int, sa syscall.Sockaddr) (err error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	sock, ok := f.sockets[fd]
	if !ok {
		return syscall.EBADF
	}

	if _, ok := f.bound[fd]; ok {
		return syscall.EINVAL
	}

	var b bound
	switch sockaddr := sa.(type) {
	case *syscall.SockaddrInet4:
		b.addr = net.IP(sockaddr.Addr[:])
		b.port = uint16(sockaddr.Port)
	case *syscall.SockaddrInet6:
		b.addr = net.IP(sockaddr.Addr[:])
		b.port = uint16(sockaddr.Port)
	default:
		return syscall.EAFNOSUPPORT
	}

	// check for port conflicts
	for ofd, o := range f.bound {
		if b.port == o.port && sock == f.sockets[ofd] {
			return syscall.EADDRINUSE
		}
	}

	f.bound[fd] = b
	return nil
}

func (f *fakeSocket) Close(fd int) (err error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	delete(f.bound, fd)
	delete(f.sockets, fd)
	return nil
}

func (f *fakeSocket) InterfaceAddrs() (addrs []net.Addr, err error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	addrs = append(addrs, f.addrs...)
	return addrs, nil
}

func (f *fakeSocket) isBound(proto lb.L4Type, ip net.IP, port uint16) bool {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	var typ int
	switch proto {
	case lb.UDP:
		typ = syscall.SOCK_DGRAM
	case lb.TCP:
		typ = syscall.SOCK_STREAM
	default:
		return false
	}

	for fd, b := range f.bound {
		if b.addr.Equal(ip) && b.port == port && f.sockets[fd].typ == typ {
			return true
		}
	}
	return false
}

func (f *fakeSocket) addInterfaceAddr(cidr *net.IPNet) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	f.addrs = append(f.addrs, cidr)
}
