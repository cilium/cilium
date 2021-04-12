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

// +build linux

package arp

import (
	"net"
	"os"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// protoARP is the uint16 EtherType representation of ARP (Address
// Resolution Protocol, RFC 826). 0x0608 is htons(0x0806) as we need it
// in network byte order
const protoARP = 0x0608

var _ net.PacketConn = &packetConn{}

type packetConn struct {
	link netlink.Link
	s    *arpSocket
}

func listen(link netlink.Link) (*packetConn, error) {
	us, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, protoARP)
	if err != nil {
		return nil, err
	}

	if err := unix.SetNonblock(us, true); err != nil {
		unix.Close(us)
		return nil, err
	}

	// if the socket is non-blocking, this returns a pollable resource
	// which is needed for Set*Deadline() methods to work
	f := os.NewFile(uintptr(us), "arp-socket")
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}

	as := &arpSocket{
		f:  f,
		rc: rc,
	}

	pc := &packetConn{
		link: link,
		s:    as,
	}

	return pc, nil
}

func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := p.s.RecvTo(b, 0)
	if err != nil {
		return n, nil, err
	}

	sa, ok := addr.(*unix.SockaddrLinklayer)
	if !ok {
		return n, nil, unix.EINVAL
	}

	mac := make(net.HardwareAddr, sa.Halen)
	copy(mac, sa.Addr[:])
	return n, &Addr{
		HardwareAddr: mac,
	}, nil
}

func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	a, ok := addr.(*Addr)
	if !ok || a.HardwareAddr == nil {
		return 0, unix.EINVAL
	}

	var baddr [8]byte
	copy(baddr[:], a.HardwareAddr)

	err := p.s.SendFrom(b, 0, &unix.SockaddrLinklayer{
		Ifindex:  p.link.Attrs().Index,
		Halen:    uint8(len(baddr)),
		Addr:     baddr,
		Protocol: protoARP,
	})

	return len(b), err
}

func (p *packetConn) Close() error {
	return p.s.Close()
}

func (p *packetConn) LocalAddr() net.Addr {
	return &Addr{
		HardwareAddr: p.link.Attrs().HardwareAddr,
	}
}

func (p *packetConn) SetDeadline(t time.Time) error {
	return p.s.SetDeadline(t)
}

func (p *packetConn) SetReadDeadline(time.Time) error {
	return ErrNotImplemented
}

func (p *packetConn) SetWriteDeadline(time.Time) error {
	return ErrNotImplemented
}

type arpSocket struct {
	f  *os.File
	rc syscall.RawConn
}

func (a *arpSocket) RecvTo(p []byte, flags int) (int, unix.Sockaddr, error) {
	var (
		n    int
		addr unix.Sockaddr
		err  error
	)

	rerr := a.rc.Read(func(fd uintptr) bool {
		n, addr, err = unix.Recvfrom(int(fd), p, flags)
		return !ignorable(err)
	})

	if rerr != nil {
		return n, addr, rerr
	}

	return n, addr, err
}

func (a *arpSocket) SendFrom(p []byte, flags int, to unix.Sockaddr) error {
	var err error

	werr := a.rc.Write(func(fd uintptr) bool {
		err = unix.Sendto(int(fd), p, flags, to)
		return !ignorable(err)
	})

	if werr != nil {
		return werr
	}

	return err
}

func (a *arpSocket) Close() error {
	return a.f.Close()
}

func (a *arpSocket) SetDeadline(t time.Time) error {
	return a.f.SetDeadline(t)
}

// Since we don't block on the socket we can get
// either EAGAIN or EINTR reading or writing to it.
// Those errors can be ignored and syscall can be retried.
func ignorable(err error) bool {
	switch err {
	case unix.EAGAIN, syscall.EINTR:
		return true
	default:
		return false
	}
}
