/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (
	_ Bind = (*StdNetBind)(nil)
)

// StdNetBind implements Bind for all platforms except Windows.
type StdNetBind struct {
	mu           sync.Mutex // protects following fields
	ipv4         *net.UDPConn
	ipv6         *net.UDPConn
	blackhole4   bool
	blackhole6   bool
	ipv4PC       *ipv4.PacketConn
	ipv6PC       *ipv6.PacketConn
	udpAddrPool  sync.Pool
	ipv4MsgsPool sync.Pool
	ipv6MsgsPool sync.Pool
}

func NewStdNetBind() Bind {
	return &StdNetBind{
		udpAddrPool: sync.Pool{
			New: func() any {
				return &net.UDPAddr{
					IP: make([]byte, 16),
				}
			},
		},

		ipv4MsgsPool: sync.Pool{
			New: func() any {
				msgs := make([]ipv4.Message, IdealBatchSize)
				for i := range msgs {
					msgs[i].Buffers = make(net.Buffers, 1)
					msgs[i].OOB = make([]byte, srcControlSize)
				}
				return &msgs
			},
		},

		ipv6MsgsPool: sync.Pool{
			New: func() any {
				msgs := make([]ipv6.Message, IdealBatchSize)
				for i := range msgs {
					msgs[i].Buffers = make(net.Buffers, 1)
					msgs[i].OOB = make([]byte, srcControlSize)
				}
				return &msgs
			},
		},
	}
}

type StdNetEndpoint struct {
	// AddrPort is the endpoint destination.
	netip.AddrPort
	// src is the current sticky source address and interface index, if supported.
	src struct {
		netip.Addr
		ifidx int32
	}
}

var (
	_ Bind     = (*StdNetBind)(nil)
	_ Endpoint = &StdNetEndpoint{}
)

func (*StdNetBind) ParseEndpoint(s string) (Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	return asEndpoint(e), err
}

func (e *StdNetEndpoint) ClearSrc() {
	e.src.ifidx = 0
	e.src.Addr = netip.Addr{}
}

func (e *StdNetEndpoint) DstIP() netip.Addr {
	return e.AddrPort.Addr()
}

func (e *StdNetEndpoint) SrcIP() netip.Addr {
	return e.src.Addr
}

func (e *StdNetEndpoint) SrcIfidx() int32 {
	return e.src.ifidx
}

func (e *StdNetEndpoint) DstToBytes() []byte {
	b, _ := e.AddrPort.MarshalBinary()
	return b
}

func (e *StdNetEndpoint) DstToString() string {
	return e.AddrPort.String()
}

func (e *StdNetEndpoint) SrcToString() string {
	return e.src.Addr.String()
}

func listenNet(network string, port int) (*net.UDPConn, int, error) {
	conn, err := listenConfig().ListenPacket(context.Background(), network, ":"+strconv.Itoa(port))
	if err != nil {
		return nil, 0, err
	}

	// Retrieve port.
	laddr := conn.LocalAddr()
	uaddr, err := net.ResolveUDPAddr(
		laddr.Network(),
		laddr.String(),
	)
	if err != nil {
		return nil, 0, err
	}
	return conn.(*net.UDPConn), uaddr.Port, nil
}

func (s *StdNetBind) Open(uport uint16) ([]ReceiveFunc, uint16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err error
	var tries int

	if s.ipv4 != nil || s.ipv6 != nil {
		return nil, 0, ErrBindAlreadyOpen
	}

	// Attempt to open ipv4 and ipv6 listeners on the same port.
	// If uport is 0, we can retry on failure.
again:
	port := int(uport)
	var v4conn, v6conn *net.UDPConn

	v4conn, port, err = listenNet("udp4", port)
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		return nil, 0, err
	}

	// Listen on the same port as we're using for ipv4.
	v6conn, port, err = listenNet("udp6", port)
	if uport == 0 && errors.Is(err, syscall.EADDRINUSE) && tries < 100 {
		v4conn.Close()
		tries++
		goto again
	}
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		v4conn.Close()
		return nil, 0, err
	}
	var fns []ReceiveFunc
	if v4conn != nil {
		fns = append(fns, s.receiveIPv4)
		s.ipv4 = v4conn
	}
	if v6conn != nil {
		fns = append(fns, s.receiveIPv6)
		s.ipv6 = v6conn
	}
	if len(fns) == 0 {
		return nil, 0, syscall.EAFNOSUPPORT
	}

	s.ipv4PC = ipv4.NewPacketConn(s.ipv4)
	s.ipv6PC = ipv6.NewPacketConn(s.ipv6)

	return fns, uint16(port), nil
}

func (s *StdNetBind) receiveIPv4(buffs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
	msgs := s.ipv4MsgsPool.Get().(*[]ipv4.Message)
	defer s.ipv4MsgsPool.Put(msgs)
	for i := range buffs {
		(*msgs)[i].Buffers[0] = buffs[i]
	}
	numMsgs, err := s.ipv4PC.ReadBatch(*msgs, 0)
	if err != nil {
		return 0, err
	}
	for i := 0; i < numMsgs; i++ {
		msg := &(*msgs)[i]
		sizes[i] = msg.N
		addrPort := msg.Addr.(*net.UDPAddr).AddrPort()
		ep := asEndpoint(addrPort)
		getSrcFromControl(msg.OOB, ep)
		eps[i] = ep
	}
	return numMsgs, nil
}

func (s *StdNetBind) receiveIPv6(buffs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
	msgs := s.ipv6MsgsPool.Get().(*[]ipv6.Message)
	defer s.ipv6MsgsPool.Put(msgs)
	for i := range buffs {
		(*msgs)[i].Buffers[0] = buffs[i]
	}
	numMsgs, err := s.ipv6PC.ReadBatch(*msgs, 0)
	if err != nil {
		return 0, err
	}
	for i := 0; i < numMsgs; i++ {
		msg := &(*msgs)[i]
		sizes[i] = msg.N
		addrPort := msg.Addr.(*net.UDPAddr).AddrPort()
		ep := asEndpoint(addrPort)
		getSrcFromControl(msg.OOB, ep)
		eps[i] = ep
	}
	return numMsgs, nil
}

// TODO: When all Binds handle IdealBatchSize, remove this dynamic function and
// rename the IdealBatchSize constant to BatchSize.
func (s *StdNetBind) BatchSize() int {
	return IdealBatchSize
}

func (s *StdNetBind) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err1, err2 error
	if s.ipv4 != nil {
		err1 = s.ipv4.Close()
		s.ipv4 = nil
	}
	if s.ipv6 != nil {
		err2 = s.ipv6.Close()
		s.ipv6 = nil
	}
	s.blackhole4 = false
	s.blackhole6 = false
	if err1 != nil {
		return err1
	}
	return err2
}

func (s *StdNetBind) Send(buffs [][]byte, endpoint Endpoint) error {
	s.mu.Lock()
	blackhole := s.blackhole4
	conn := s.ipv4
	is6 := false
	if endpoint.DstIP().Is6() {
		blackhole = s.blackhole6
		conn = s.ipv6
		is6 = true
	}
	s.mu.Unlock()

	if blackhole {
		return nil
	}
	if conn == nil {
		return syscall.EAFNOSUPPORT
	}
	if is6 {
		return s.send6(s.ipv6PC, endpoint, buffs)
	} else {
		return s.send4(s.ipv4PC, endpoint, buffs)
	}
}

func (s *StdNetBind) send4(conn *ipv4.PacketConn, ep Endpoint, buffs [][]byte) error {
	ua := s.udpAddrPool.Get().(*net.UDPAddr)
	as4 := ep.DstIP().As4()
	copy(ua.IP, as4[:])
	ua.IP = ua.IP[:4]
	ua.Port = int(ep.(*StdNetEndpoint).Port())
	msgs := s.ipv4MsgsPool.Get().(*[]ipv4.Message)
	for i, buff := range buffs {
		(*msgs)[i].Buffers[0] = buff
		(*msgs)[i].Addr = ua
		setSrcControl(&(*msgs)[i].OOB, ep.(*StdNetEndpoint))
	}
	var (
		n     int
		err   error
		start int
	)
	for {
		n, err = conn.WriteBatch((*msgs)[start:len(buffs)], 0)
		if err != nil || n == len((*msgs)[start:len(buffs)]) {
			break
		}
		start += n
	}
	s.udpAddrPool.Put(ua)
	s.ipv4MsgsPool.Put(msgs)
	return err
}

func (s *StdNetBind) send6(conn *ipv6.PacketConn, ep Endpoint, buffs [][]byte) error {
	ua := s.udpAddrPool.Get().(*net.UDPAddr)
	as16 := ep.DstIP().As16()
	copy(ua.IP, as16[:])
	ua.IP = ua.IP[:16]
	ua.Port = int(ep.(*StdNetEndpoint).Port())
	msgs := s.ipv6MsgsPool.Get().(*[]ipv6.Message)
	for i, buff := range buffs {
		(*msgs)[i].Buffers[0] = buff
		(*msgs)[i].Addr = ua
		setSrcControl(&(*msgs)[i].OOB, ep.(*StdNetEndpoint))
	}
	var (
		n     int
		err   error
		start int
	)
	for {
		n, err = conn.WriteBatch((*msgs)[start:len(buffs)], 0)
		if err != nil || n == len((*msgs)[start:len(buffs)]) {
			break
		}
		start += n
	}
	s.udpAddrPool.Put(ua)
	s.ipv6MsgsPool.Put(msgs)
	return err
}

// endpointPool contains a re-usable set of mapping from netip.AddrPort to Endpoint.
// This exists to reduce allocations: Putting a netip.AddrPort in an Endpoint allocates,
// but Endpoints are immutable, so we can re-use them.
var endpointPool = sync.Pool{
	New: func() any {
		return make(map[netip.AddrPort]*StdNetEndpoint)
	},
}

// asEndpoint returns an Endpoint containing ap.
func asEndpoint(ap netip.AddrPort) *StdNetEndpoint {
	m := endpointPool.Get().(map[netip.AddrPort]*StdNetEndpoint)
	defer endpointPool.Put(m)
	e, ok := m[ap]
	if !ok {
		e = &StdNetEndpoint{AddrPort: ap}
		m[ap] = e
	}
	return e
}
