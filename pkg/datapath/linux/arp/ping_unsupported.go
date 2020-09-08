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

// +build !linux

package arp

import (
	"net"
	"time"

	"github.com/vishvananda/netlink"
)

var _ net.PacketConn = &unsupportedConn{}

type unsupportedConn struct{}

func listen(link netlink.Link) (*unsupportedConn, error) {
	return &unsupportedConn{}, nil
}

func (u unsupportedConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, nil, ErrNotImplemented
}

func (u unsupportedConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return 0, ErrNotImplemented
}

func (u unsupportedConn) Close() error {
	return ErrNotImplemented
}

func (u unsupportedConn) LocalAddr() net.Addr {
	return nil
}

func (u unsupportedConn) SetDeadline(t time.Time) error {
	return ErrNotImplemented
}

func (u unsupportedConn) SetReadDeadline(t time.Time) error {
	return ErrNotImplemented
}

func (u unsupportedConn) SetWriteDeadline(t time.Time) error {
	return ErrNotImplemented
}
