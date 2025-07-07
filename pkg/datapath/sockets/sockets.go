// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sockets

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	sizeofSocketID      = 0x30
	sizeofSocketRequest = sizeofSocketID + 0x8
	sizeofSocket        = sizeofSocketID + 0x18
	SOCK_DESTROY        = 21
)

var (
	native       = binary.NativeEndian
	networkOrder = binary.BigEndian
)

func stateMask(ms ...int) uint32 {
	var out uint32
	for _, m := range ms {
		out |= 1 << m
	}
	return out
}

// StateFilterTCP is a mask of all states we consider for socket termination.
// Instead of destroying all states, we make some notable omissions which are
// documented below:
//
//   - TCP_CLOSE: Calls to close a socket in TCP_CLOSE state will result in
//     ENOENT, this is also confusing as it is the same err code returned
//     when a socket that doesn't exist is destroyed.
//
//   - TCP_TIME_WAIT: Socket may enter this state post close/FIN-wait states
//     to catch any leftover traffic that may not have arrived yet. This is
//     for security reasons, as well as avoiding late traffic from entering
//     a new socket bound to the same addr/port. Technically, for the socket
//     LB its not necessary as we remove the key from the rev NAT map in the
//     cil_sock_release() hook, so these sockets won't be found. On the other
//     hand we also do not need to waste time to iterate them.
var StateFilterTCP = stateMask(
	// The following states emit RST (net/ipv4/tcp.c#L3228-L3235)
	netlink.TCP_ESTABLISHED,
	netlink.TCP_CLOSE_WAIT,
	netlink.TCP_FIN_WAIT1,
	netlink.TCP_FIN_WAIT2,
	netlink.TCP_SYN_RECV,
	// Sockets in SYN-RECV state are simply removed from request queue
	// and freed in memory (net/ipv4/tcp.c#L4878-L4885)
	netlink.TCP_NEW_SYN_REC,
	// Sockets in TCP_LISTEN are moved to closing state
	// (net/ipv4/tcp.c#L4908)
	netlink.TCP_CLOSE,
	// Following are handled without any special consideration/just closed
	netlink.TCP_SYN_SENT,
	netlink.TCP_CLOSING,
	netlink.TCP_LAST_ACK,
	netlink.TCP_LISTEN,
)

// StateFilterUDP is a mask of all states we consider for socket termination.
// There are no state omissions.
const StateFilterUDP = 0xffff

// Iterate iterates netlink sockets via a callback.
func Iterate(proto uint8, family uint8, stateFilter uint32, fn func(*netlink.Socket, error) error) error {
	return iterate(proto, family, stateFilter, func(s *Socket, err error) error {
		return fn((*netlink.Socket)(s), err)
	})
}

// DestroySocket sends a socket destroy message via netlink and waits for a ack response.
// This is implemented using primitives in vishvananda library, however the default SocketDestroy()
// function is insufficient for our purposes as it identifies socket only on src/dst address
// whereas this allows destroying socket precisely via the netlink.Socket object.
func DestroySocket(logger *slog.Logger, sock netlink.Socket, proto netlink.Proto, stateFilter uint32) error {
	return destroySocket(logger, sock.ID, sock.Family, uint8(proto), stateFilter, true)
}

func iterate(proto uint8, family uint8, stateFilter uint32, fn func(*Socket, error) error) error {
	switch proto {
	case unix.IPPROTO_UDP, unix.IPPROTO_TCP:
	default:
		return fmt.Errorf("unsupported protocol for iterating sockets: %d", proto)
	}
	return iterateNetlinkSockets(proto, family, stateFilter, fn)
}

type SocketDestroyer interface {
	Destroy(filter SocketFilter) error
}

type SocketFilter struct {
	DestIp   net.IP
	DestPort uint16
	Family   uint8
	Protocol uint8
	States   uint32
	// Optional callback function to determine whether a filtered socket needs to be destroyed
	DestroyCB DestroySocketCB
}

type DestroySocketCB func(id netlink.SocketID) bool

// Destroy destroys sockets matching the passed filter parameters using the
// sock_diag netlink framework.
//
// Supported families in the filter: syscall.AF_INET, syscall.AF_INET6
// Supported protocols in the filter: unix.IPPROTO_UDP, unix.IPPROTO_TCP
func Destroy(logger *slog.Logger, filter SocketFilter) error {
	family := filter.Family
	if family != syscall.AF_INET && family != syscall.AF_INET6 {
		return fmt.Errorf("unsupported family for socket destroy: %d", family)
	}
	var errs error
	success, failed := 0, 0

	// Query sockets matching the passed filter, and then destroy the filtered
	// sockets.
	switch filter.Protocol {
	case unix.IPPROTO_UDP, unix.IPPROTO_TCP:
	redo:
		err := filterAndDestroySockets(family, filter.Protocol, filter.States, func(sock netlink.SocketID, err error) {
			if err != nil {
				errs = errors.Join(errs, fmt.Errorf("socket with filter [%v]: %w", filter, err))
				failed++
				return
			}
			if filter.MatchSocket(sock) {
				logger.Info("", logfields.Socket, sock)
				if err := destroySocket(logger, sock, family, filter.Protocol, filter.States, true); err != nil {
					errs = errors.Join(errs, fmt.Errorf("destroying socket with filter [%v]: %w", filter, err))
					failed++
					return
				}
				logger.Debug("Destroyed socket", logfields.Socket, sock)
				success++
			}
		})
		if err != nil {
			return fmt.Errorf("failed to get sockets with filter %v: %w", filter, err)
		}
		// After we iterated all IPv4 sockets, we now need to do the same
		// also for IPv6 client sockets given they can have IPv4-in-IPv6
		// mapped addresses and got connected to the terminating IPv4
		// backend this way.
		//
		// Note that socketlb placed the revnat entry into the IPv4-related
		// map (not the IPv6 one!). The DestroyCB looks up the right revnat
		// BPF map based on the filter.DestIp which in our case is an IPv4
		// address. The filter.DestIp stores the IPv4 address internally
		// as IPv4-mapped IPv6 form as per net.IP.
		if family == syscall.AF_INET {
			family = syscall.AF_INET6
			goto redo
		}
	default:
		return fmt.Errorf("unsupported protocol for socket destroy: %d", filter.Protocol)
	}
	if success > 0 || failed > 0 || errs != nil {
		logger.Info(
			"Forcefully terminated sockets",
			logfields.Filter, filter,
			logfields.Success, success,
			logfields.Failed, failed,
			logfields.Errors, errs,
		)
	}

	return nil
}

func (f *SocketFilter) MatchSocket(socket netlink.SocketID) bool {
	if socket.Destination.Equal(f.DestIp) && socket.DestinationPort == f.DestPort {
		if f.DestroyCB == nil || f.DestroyCB(socket) {
			return true
		}
	}

	return false
}

func filterAndDestroySockets(family, protocol uint8, states uint32, socketCB func(socket netlink.SocketID, err error)) error {
	return iterateNetlinkSockets(protocol, family, states, func(sockInfo *Socket, err error) error {
		socketCB(sockInfo.ID, err)
		return nil
	})
}

// SocketRequest implements netlink.NetlinkRequestData to be used
// to send socket requests to netlink.
type SocketRequest struct {
	Family   uint8
	Protocol uint8
	Ext      uint8
	pad      uint8
	States   uint32
	ID       netlink.SocketID
}

func (r SocketRequest) Serialize() []byte {
	var bb bytes.Buffer

	bb.Grow(sizeofSocketRequest)

	bb.WriteByte(r.Family)
	bb.WriteByte(r.Protocol)
	bb.WriteByte(r.Ext)
	bb.WriteByte(r.pad)
	b := bb.AvailableBuffer()
	b = native.AppendUint32(b, r.States)
	b = networkOrder.AppendUint16(b, r.ID.SourcePort)
	b = networkOrder.AppendUint16(b, r.ID.DestinationPort)
	bb.Write(b)
	serializeAddr(&bb, r.Family, r.ID.Source)
	serializeAddr(&bb, r.Family, r.ID.Destination)
	b = bb.AvailableBuffer()
	b = native.AppendUint32(b, r.ID.Interface)
	b = native.AppendUint32(b, r.ID.Cookie[0])
	b = native.AppendUint32(b, r.ID.Cookie[1])
	bb.Write(b)

	return bb.Bytes()
}

func (r *SocketRequest) Len() int { return sizeofSocketRequest }

func serializeAddr(bb *bytes.Buffer, family uint8, addr net.IP) {
	if addr == nil {
		for range net.IPv6len {
			bb.WriteByte(0)
		}
		return
	}
	if family == unix.AF_INET6 {
		bb.Write(addr)
	} else {
		bb.Write(addr.To4())
		for range net.IPv6len - net.IPv4len {
			bb.WriteByte(0)
		}
	}
}

// Socket is an alias of the netlink library Socket
// type but it implements deserialization functions.
type Socket netlink.Socket

// Deserialize accepts raw byte data of a netlink socket diag response
// and deserializes it into the target socket.
func (s *Socket) Deserialize(b []byte) error {
	// early size check to guarantee safety of reads below
	if len(b) < sizeofSocket {
		return fmt.Errorf("socket data short read (%d); want %d", len(b), sizeofSocket)
	}

	bb := bytes.NewBuffer(b)
	s.Family, _ = bb.ReadByte()
	s.State, _ = bb.ReadByte()
	s.Timer, _ = bb.ReadByte()
	s.Retrans, _ = bb.ReadByte()
	s.ID.SourcePort = networkOrder.Uint16(bb.Next(2))
	s.ID.DestinationPort = networkOrder.Uint16(bb.Next(2))
	if s.Family == unix.AF_INET6 {
		s.ID.Source = net.IP(bb.Next(net.IPv6len))
		s.ID.Destination = net.IP(bb.Next(net.IPv6len))
	} else {
		src := bb.Next(net.IPv6len)
		s.ID.Source = net.IPv4(src[0], src[1], src[2], src[3])
		dst := bb.Next(net.IPv6len)
		s.ID.Destination = net.IPv4(dst[0], dst[1], dst[2], dst[3])
	}
	s.ID.Interface = native.Uint32(bb.Next(4))
	s.ID.Cookie[0] = native.Uint32(bb.Next(4))
	s.ID.Cookie[1] = native.Uint32(bb.Next(4))
	s.Expires = native.Uint32(bb.Next(4))
	s.RQueue = native.Uint32(bb.Next(4))
	s.WQueue = native.Uint32(bb.Next(4))
	s.UID = native.Uint32(bb.Next(4))
	s.INode = native.Uint32(bb.Next(4))
	return nil
}

func destroySocket(logger *slog.Logger, sockId netlink.SocketID, family uint8, protocol uint8, stateFilter uint32, waitForAck bool) error {
	s, err := openSubscribeHandle()
	if err != nil {
		return err
	}
	defer s.Close()

	params := unix.NLM_F_REQUEST
	if waitForAck {
		params |= unix.NLM_F_ACK
	}
	req := nl.NewNetlinkRequest(SOCK_DESTROY, params)
	req.AddData(&SocketRequest{
		Family:   family,
		Protocol: protocol,
		States:   stateFilter,
		ID:       sockId,
	})
	err = s.Send(req)
	if err != nil {
		return fmt.Errorf("error in destroying socket: %w", err)
	}

	if !waitForAck {
		return nil
	}
	msg, _, err := s.Receive()
	if err != nil {
		return fmt.Errorf("failed to recv destroy resp: %w", err)
	}
	for _, m := range msg {
		switch m.Header.Type {
		case unix.NLMSG_ERROR:
			error := int32(native.Uint32(m.Data[0:4]))
			errno := syscall.Errno(-error)
			if errno != 0 {
				return fmt.Errorf("got error response to socket destroy: %w", errno)
			}
			return nil
		default:
			logger.Info("netlink socket delete received was followed by an unexpected response header type.",
				logfields.Type, m.Header.Type,
			)
		}
	}

	return err
}

// openSubscribeHandle opens a netlink socket sub.
func openSubscribeHandle() (*nl.NetlinkSocket, error) {
	return nl.Subscribe(unix.NETLINK_INET_DIAG)
}

func iterateNetlinkSockets(proto uint8, family uint8, stateFilter uint32, fn func(*Socket, error) error) error {
	s, err := openSubscribeHandle()
	if err != nil {
		return err
	}
	defer s.Close()

	req := nl.NewNetlinkRequest(nl.SOCK_DIAG_BY_FAMILY, unix.NLM_F_DUMP)
	req.AddData(&SocketRequest{
		Family:   family,
		Protocol: uint8(proto),
		States:   stateFilter,
	})
	if err := s.Send(req); err != nil {
		return fmt.Errorf("failed to send netlink list request: %w", err)
	}

loop:
	for {
		msgs, from, err := s.Receive()
		if err != nil {
			fn(nil, err)
			continue loop
		}
		if from.Pid != nl.PidKernel {
			fn(nil, fmt.Errorf("Wrong sender portid %d, expected %d", from.Pid, nl.PidKernel))
			continue loop
		}
		if len(msgs) == 0 {
			fn(nil, errors.New("no message nor error from netlink"))
			continue loop
		}

		for _, m := range msgs {
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				break loop
			case unix.NLMSG_ERROR:
				error := int32(native.Uint32(m.Data[0:4]))
				fn(nil, syscall.Errno(-error))
				continue loop
			}
			sockInfo := &Socket{}
			err := sockInfo.Deserialize(m.Data)
			if err := fn(sockInfo, err); err != nil {
				return err
			}
		}
	}
	return nil
}
