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

package service

import (
	"net"
	"syscall"
)

// socket is used to mock socket-related system calls
type socket interface {
	// Socket refers to syscall.Socket
	Socket(domain, typ, proto int) (fd int, err error)
	// Bind refers to syscall.Bind
	Bind(fd int, sa syscall.Sockaddr) (err error)
	// Close refers to syscall.Close
	Close(fd int) (err error)
	// InterfaceAddrs refers to net.InterfaceAddrs
	InterfaceAddrs() (addrs []net.Addr, err error)
}

// nativeSocket forwards all calls to the native implementations
type nativeSocket struct{}

func (n *nativeSocket) Socket(domain, typ, proto int) (fd int, err error) {
	return syscall.Socket(domain, typ, proto)
}

func (n *nativeSocket) Bind(fd int, sa syscall.Sockaddr) (err error) {
	return syscall.Bind(fd, sa)
}

func (n *nativeSocket) Close(fd int) (err error) {
	return syscall.Close(fd)
}

func (n *nativeSocket) InterfaceAddrs() (addrs []net.Addr, err error) {
	return net.InterfaceAddrs()
}
