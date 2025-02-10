// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sockets

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	sizeofSocketID      = 0x30
	sizeofSocketRequest = sizeofSocketID + 0x8
	sizeofSocket        = sizeofSocketID + 0x18
	SOCK_DESTROY        = 21
)

var (
	log          = logging.DefaultLogger.WithField(logfields.LogSubsys, "datapath-sockets")
	native       = binary.NativeEndian
	networkOrder = binary.BigEndian
)

type SocketDestroyer interface {
	Destroy(filter SocketFilter) error
}

type SocketFilter struct {
	DestIp   net.IP
	DestPort uint16
	Family   uint8
	Protocol uint8
	// Optional callback function to determine whether a filtered socket needs to be destroyed
	DestroyCB DestroySocketCB
}

type DestroySocketCB func(id netlink.SocketID) bool

// Destroy destroys sockets matching the passed filter parameters using the
// sock_diag netlink framework.
//
// Supported families in the filter: syscall.AF_INET, syscall.AF_INET6
// Supported protocols in the filter: unix.IPPROTO_UDP
func Destroy(filter SocketFilter) error {
	family := filter.Family
	protocol := filter.Protocol

	if family != syscall.AF_INET && family != syscall.AF_INET6 {
		return fmt.Errorf("unsupported family for socket destroy: %d", family)
	}
	var errs error
	success, failed := 0, 0

	// Query sockets matching the passed filter, and then destroy the filtered
	// sockets.
	switch protocol {
	case unix.IPPROTO_UDP:
		err := filterAndDestroyUDPSockets(family, func(sock netlink.SocketID, err error) {
			if err != nil {
				errs = errors.Join(errs, fmt.Errorf("UDP socket with filter [%v]: %w", filter, err))
				failed++
				return
			}
			if filter.MatchSocket(sock) {
				log.Infof("socket %v", sock)
				if err := destroySocket(sock, family, unix.IPPROTO_UDP); err != nil {
					errs = errors.Join(errs, fmt.Errorf("destroying UDP socket with filter [%v]: %w", filter, err))
					failed++
					return
				}
				log.Debugf("Destroyed socket: %v", sock)
				success++
			}
		})
		if err != nil {
			return fmt.Errorf("failed to get sockets with filter %v: %w", filter, err)
		}

	default:
		return fmt.Errorf("unsupported protocol for socket destroy: %d", protocol)
	}
	if success > 0 || failed > 0 || errs != nil {
		log.WithFields(logrus.Fields{
			"filter":  filter,
			"success": success,
			"failed":  failed,
			"errors":  errs,
		}).Info("Forcefully terminated sockets")
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

func filterAndDestroyUDPSockets(family uint8, socketCB func(socket netlink.SocketID, err error)) error {
	return iterateNetlinkSockets(unix.IPPROTO_UDP, syscall.AF_INET, 0xffff, func(sockInfo *Socket, err error) error {
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

func destroySocket(sockId netlink.SocketID, family uint8, protocol uint8) error {
	s, err := nl.Subscribe(unix.NETLINK_INET_DIAG)
	if err != nil {
		return err
	}
	defer s.Close()

	req := nl.NewNetlinkRequest(SOCK_DESTROY, unix.NLM_F_REQUEST)
	req.AddData(&SocketRequest{
		Family:   family,
		Protocol: protocol,
		States:   uint32(0xfff),
		ID:       sockId,
	})
	err = s.Send(req)
	if err != nil {
		fmt.Printf("error in destroying socket: %v", sockId)
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
