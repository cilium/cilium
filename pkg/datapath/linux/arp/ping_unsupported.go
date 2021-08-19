// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

//go:build !linux
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
