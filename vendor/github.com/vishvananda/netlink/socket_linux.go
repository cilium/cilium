package netlink

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const (
	sizeofSocketID          = 0x30
	sizeofSocketRequest     = sizeofSocketID + 0x8
	sizeofSocket            = sizeofSocketID + 0x18
	sizeofUnixSocketRequest = 0x18 // 24 byte
	sizeofUnixSocket        = 0x10 // 16 byte
)

type socketRequest struct {
	Family   uint8
	Protocol uint8
	Ext      uint8
	pad      uint8
	States   uint32
	ID       SocketID
}

type writeBuffer struct {
	Bytes []byte
	pos   int
}

func (b *writeBuffer) Write(c byte) {
	b.Bytes[b.pos] = c
	b.pos++
}

func (b *writeBuffer) Next(n int) []byte {
	s := b.Bytes[b.pos : b.pos+n]
	b.pos += n
	return s
}

func (r *socketRequest) Serialize() []byte {
	b := writeBuffer{Bytes: make([]byte, sizeofSocketRequest)}
	b.Write(r.Family)
	b.Write(r.Protocol)
	b.Write(r.Ext)
	b.Write(r.pad)
	native.PutUint32(b.Next(4), r.States)
	networkOrder.PutUint16(b.Next(2), r.ID.SourcePort)
	networkOrder.PutUint16(b.Next(2), r.ID.DestinationPort)
	if r.Family == unix.AF_INET6 {
		copy(b.Next(16), r.ID.Source)
		copy(b.Next(16), r.ID.Destination)
	} else {
		copy(b.Next(4), r.ID.Source.To4())
		b.Next(12)
		copy(b.Next(4), r.ID.Destination.To4())
		b.Next(12)
	}
	native.PutUint32(b.Next(4), r.ID.Interface)
	native.PutUint32(b.Next(4), r.ID.Cookie[0])
	native.PutUint32(b.Next(4), r.ID.Cookie[1])
	return b.Bytes
}

func (r *socketRequest) Len() int { return sizeofSocketRequest }

// According to linux/include/uapi/linux/unix_diag.h
type unixSocketRequest struct {
	Family   uint8
	Protocol uint8
	pad      uint16
	States   uint32
	INode    uint32
	Show     uint32
	Cookie   [2]uint32
}

func (r *unixSocketRequest) Serialize() []byte {
	b := writeBuffer{Bytes: make([]byte, sizeofUnixSocketRequest)}
	b.Write(r.Family)
	b.Write(r.Protocol)
	native.PutUint16(b.Next(2), r.pad)
	native.PutUint32(b.Next(4), r.States)
	native.PutUint32(b.Next(4), r.INode)
	native.PutUint32(b.Next(4), r.Show)
	native.PutUint32(b.Next(4), r.Cookie[0])
	native.PutUint32(b.Next(4), r.Cookie[1])
	return b.Bytes
}

func (r *unixSocketRequest) Len() int { return sizeofUnixSocketRequest }

type readBuffer struct {
	Bytes []byte
	pos   int
}

func (b *readBuffer) Read() byte {
	c := b.Bytes[b.pos]
	b.pos++
	return c
}

func (b *readBuffer) Next(n int) []byte {
	s := b.Bytes[b.pos : b.pos+n]
	b.pos += n
	return s
}

func (s *Socket) deserialize(b []byte) error {
	if len(b) < sizeofSocket {
		return fmt.Errorf("socket data short read (%d); want %d", len(b), sizeofSocket)
	}
	rb := readBuffer{Bytes: b}
	s.Family = rb.Read()
	s.State = rb.Read()
	s.Timer = rb.Read()
	s.Retrans = rb.Read()
	s.ID.SourcePort = networkOrder.Uint16(rb.Next(2))
	s.ID.DestinationPort = networkOrder.Uint16(rb.Next(2))
	if s.Family == unix.AF_INET6 {
		s.ID.Source = net.IP(rb.Next(16))
		s.ID.Destination = net.IP(rb.Next(16))
	} else {
		s.ID.Source = net.IPv4(rb.Read(), rb.Read(), rb.Read(), rb.Read())
		rb.Next(12)
		s.ID.Destination = net.IPv4(rb.Read(), rb.Read(), rb.Read(), rb.Read())
		rb.Next(12)
	}
	s.ID.Interface = native.Uint32(rb.Next(4))
	s.ID.Cookie[0] = native.Uint32(rb.Next(4))
	s.ID.Cookie[1] = native.Uint32(rb.Next(4))
	s.Expires = native.Uint32(rb.Next(4))
	s.RQueue = native.Uint32(rb.Next(4))
	s.WQueue = native.Uint32(rb.Next(4))
	s.UID = native.Uint32(rb.Next(4))
	s.INode = native.Uint32(rb.Next(4))
	return nil
}

func (u *UnixSocket) deserialize(b []byte) error {
	if len(b) < sizeofUnixSocket {
		return fmt.Errorf("unix diag data short read (%d); want %d", len(b), sizeofUnixSocket)
	}
	rb := readBuffer{Bytes: b}
	u.Type = rb.Read()
	u.Family = rb.Read()
	u.State = rb.Read()
	u.pad = rb.Read()
	u.INode = native.Uint32(rb.Next(4))
	u.Cookie[0] = native.Uint32(rb.Next(4))
	u.Cookie[1] = native.Uint32(rb.Next(4))
	return nil
}

// SocketGet returns the Socket identified by its local and remote addresses.
func SocketGet(local, remote net.Addr) (*Socket, error) {
	localTCP, ok := local.(*net.TCPAddr)
	if !ok {
		return nil, ErrNotImplemented
	}
	remoteTCP, ok := remote.(*net.TCPAddr)
	if !ok {
		return nil, ErrNotImplemented
	}
	localIP := localTCP.IP.To4()
	if localIP == nil {
		return nil, ErrNotImplemented
	}
	remoteIP := remoteTCP.IP.To4()
	if remoteIP == nil {
		return nil, ErrNotImplemented
	}

	s, err := nl.Subscribe(unix.NETLINK_INET_DIAG)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	req := nl.NewNetlinkRequest(nl.SOCK_DIAG_BY_FAMILY, 0)
	req.AddData(&socketRequest{
		Family:   unix.AF_INET,
		Protocol: unix.IPPROTO_TCP,
		ID: SocketID{
			SourcePort:      uint16(localTCP.Port),
			DestinationPort: uint16(remoteTCP.Port),
			Source:          localIP,
			Destination:     remoteIP,
			Cookie:          [2]uint32{nl.TCPDIAG_NOCOOKIE, nl.TCPDIAG_NOCOOKIE},
		},
	})
	s.Send(req)
	msgs, from, err := s.Receive()
	if err != nil {
		return nil, err
	}
	if from.Pid != nl.PidKernel {
		return nil, fmt.Errorf("wrong sender portid %d, expected %d", from.Pid, nl.PidKernel)
	}
	if len(msgs) == 0 {
		return nil, errors.New("no message nor error from netlink")
	}
	if len(msgs) > 2 {
		return nil, fmt.Errorf("multiple (%d) matching sockets", len(msgs))
	}
	sock := &Socket{}
	if err := sock.deserialize(msgs[0].Data); err != nil {
		return nil, err
	}
	return sock, nil
}

// SocketDiagTCPInfo requests INET_DIAG_INFO for TCP protocol for specified family type and return with extension TCP info.
func SocketDiagTCPInfo(family uint8) ([]*InetDiagTCPInfoResp, error) {
	// Construct the request
	req := nl.NewNetlinkRequest(nl.SOCK_DIAG_BY_FAMILY, unix.NLM_F_DUMP)
	req.AddData(&socketRequest{
		Family:   family,
		Protocol: unix.IPPROTO_TCP,
		Ext:      (1 << (INET_DIAG_VEGASINFO - 1)) | (1 << (INET_DIAG_INFO - 1)),
		States:   uint32(0xfff), // all states
	})

	// Do the query and parse the result
	var result []*InetDiagTCPInfoResp
	err := socketDiagExecutor(req, func(m syscall.NetlinkMessage) error {
		sockInfo := &Socket{}
		if err := sockInfo.deserialize(m.Data); err != nil {
			return err
		}
		attrs, err := nl.ParseRouteAttr(m.Data[sizeofSocket:])
		if err != nil {
			return err
		}

		res, err := attrsToInetDiagTCPInfoResp(attrs, sockInfo)
		if err != nil {
			return err
		}

		result = append(result, res)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// SocketDiagTCP requests INET_DIAG_INFO for TCP protocol for specified family type and return related socket.
func SocketDiagTCP(family uint8) ([]*Socket, error) {
	// Construct the request
	req := nl.NewNetlinkRequest(nl.SOCK_DIAG_BY_FAMILY, unix.NLM_F_DUMP)
	req.AddData(&socketRequest{
		Family:   family,
		Protocol: unix.IPPROTO_TCP,
		Ext:      (1 << (INET_DIAG_VEGASINFO - 1)) | (1 << (INET_DIAG_INFO - 1)),
		States:   uint32(0xfff), // all states
	})

	// Do the query and parse the result
	var result []*Socket
	err := socketDiagExecutor(req, func(m syscall.NetlinkMessage) error {
		sockInfo := &Socket{}
		if err := sockInfo.deserialize(m.Data); err != nil {
			return err
		}
		result = append(result, sockInfo)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// SocketDiagUDPInfo requests INET_DIAG_INFO for UDP protocol for specified family type and return with extension info.
func SocketDiagUDPInfo(family uint8) ([]*InetDiagUDPInfoResp, error) {
	// Construct the request
	var extensions uint8
	extensions = 1 << (INET_DIAG_VEGASINFO - 1)
	extensions |= 1 << (INET_DIAG_INFO - 1)
	extensions |= 1 << (INET_DIAG_MEMINFO - 1)

	req := nl.NewNetlinkRequest(nl.SOCK_DIAG_BY_FAMILY, unix.NLM_F_DUMP)
	req.AddData(&socketRequest{
		Family:   family,
		Protocol: unix.IPPROTO_UDP,
		Ext:      extensions,
		States:   uint32(0xfff), // all states
	})

	// Do the query and parse the result
	var result []*InetDiagUDPInfoResp
	err := socketDiagExecutor(req, func(m syscall.NetlinkMessage) error {
		sockInfo := &Socket{}
		if err := sockInfo.deserialize(m.Data); err != nil {
			return err
		}
		attrs, err := nl.ParseRouteAttr(m.Data[sizeofSocket:])
		if err != nil {
			return err
		}

		res, err := attrsToInetDiagUDPInfoResp(attrs, sockInfo)
		if err != nil {
			return err
		}

		result = append(result, res)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// SocketDiagUDP requests INET_DIAG_INFO for UDP protocol for specified family type and return related socket.
func SocketDiagUDP(family uint8) ([]*Socket, error) {
	// Construct the request
	req := nl.NewNetlinkRequest(nl.SOCK_DIAG_BY_FAMILY, unix.NLM_F_DUMP)
	req.AddData(&socketRequest{
		Family:   family,
		Protocol: unix.IPPROTO_UDP,
		Ext:      (1 << (INET_DIAG_VEGASINFO - 1)) | (1 << (INET_DIAG_INFO - 1)),
		States:   uint32(0xfff), // all states
	})

	// Do the query and parse the result
	var result []*Socket
	err := socketDiagExecutor(req, func(m syscall.NetlinkMessage) error {
		sockInfo := &Socket{}
		if err := sockInfo.deserialize(m.Data); err != nil {
			return err
		}
		result = append(result, sockInfo)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// UnixSocketDiagInfo requests UNIX_DIAG_INFO for unix sockets and return with extension info.
func UnixSocketDiagInfo() ([]*UnixDiagInfoResp, error) {
	// Construct the request
	var extensions uint8
	extensions = 1 << UNIX_DIAG_NAME
	extensions |= 1 << UNIX_DIAG_PEER
	extensions |= 1 << UNIX_DIAG_RQLEN
	req := nl.NewNetlinkRequest(nl.SOCK_DIAG_BY_FAMILY, unix.NLM_F_DUMP)
	req.AddData(&unixSocketRequest{
		Family: unix.AF_UNIX,
		States: ^uint32(0), // all states
		Show:   uint32(extensions),
	})

	var result []*UnixDiagInfoResp
	err := socketDiagExecutor(req, func(m syscall.NetlinkMessage) error {
		sockInfo := &UnixSocket{}
		if err := sockInfo.deserialize(m.Data); err != nil {
			return err
		}

		// Diagnosis also delivers sockets with AF_INET family, filter those
		if sockInfo.Family != unix.AF_UNIX {
			return nil
		}

		attrs, err := nl.ParseRouteAttr(m.Data[sizeofUnixSocket:])
		if err != nil {
			return err
		}

		res, err := attrsToUnixDiagInfoResp(attrs, sockInfo)
		if err != nil {
			return err
		}
		result = append(result, res)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// UnixSocketDiag requests UNIX_DIAG_INFO for unix sockets.
func UnixSocketDiag() ([]*UnixSocket, error) {
	// Construct the request
	req := nl.NewNetlinkRequest(nl.SOCK_DIAG_BY_FAMILY, unix.NLM_F_DUMP)
	req.AddData(&unixSocketRequest{
		Family: unix.AF_UNIX,
		States: ^uint32(0), // all states
	})

	var result []*UnixSocket
	err := socketDiagExecutor(req, func(m syscall.NetlinkMessage) error {
		sockInfo := &UnixSocket{}
		if err := sockInfo.deserialize(m.Data); err != nil {
			return err
		}

		// Diagnosis also delivers sockets with AF_INET family, filter those
		if sockInfo.Family == unix.AF_UNIX {
			result = append(result, sockInfo)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// socketDiagExecutor requests diagnoses info from the NETLINK_INET_DIAG socket for the specified request.
func socketDiagExecutor(req *nl.NetlinkRequest, receiver func(syscall.NetlinkMessage) error) error {
	s, err := nl.Subscribe(unix.NETLINK_INET_DIAG)
	if err != nil {
		return err
	}
	defer s.Close()
	s.Send(req)

loop:
	for {
		msgs, from, err := s.Receive()
		if err != nil {
			return err
		}
		if from.Pid != nl.PidKernel {
			return fmt.Errorf("wrong sender portid %d, expected %d", from.Pid, nl.PidKernel)
		}
		if len(msgs) == 0 {
			return errors.New("no message nor error from netlink")
		}

		for _, m := range msgs {
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				break loop
			case unix.NLMSG_ERROR:
				error := int32(native.Uint32(m.Data[0:4]))
				return syscall.Errno(-error)
			}
			if err := receiver(m); err != nil {
				return err
			}
		}
	}
	return nil
}

func attrsToInetDiagTCPInfoResp(attrs []syscall.NetlinkRouteAttr, sockInfo *Socket) (*InetDiagTCPInfoResp, error) {
	info := &InetDiagTCPInfoResp{
		InetDiagMsg: sockInfo,
	}
	for _, a := range attrs {
		switch a.Attr.Type {
		case INET_DIAG_INFO:
			info.TCPInfo = &TCPInfo{}
			if err := info.TCPInfo.deserialize(a.Value); err != nil {
				return nil, err
			}
		case INET_DIAG_BBRINFO:
			info.TCPBBRInfo = &TCPBBRInfo{}
			if err := info.TCPBBRInfo.deserialize(a.Value); err != nil {
				return nil, err
			}
		}
	}

	return info, nil
}

func attrsToInetDiagUDPInfoResp(attrs []syscall.NetlinkRouteAttr, sockInfo *Socket) (*InetDiagUDPInfoResp, error) {
	info := &InetDiagUDPInfoResp{
		InetDiagMsg: sockInfo,
	}
	for _, a := range attrs {
		switch a.Attr.Type {
		case INET_DIAG_MEMINFO:
			info.Memory = &MemInfo{}
			if err := info.Memory.deserialize(a.Value); err != nil {
				return nil, err
			}
		}
	}

	return info, nil
}

func attrsToUnixDiagInfoResp(attrs []syscall.NetlinkRouteAttr, sockInfo *UnixSocket) (*UnixDiagInfoResp, error) {
	info := &UnixDiagInfoResp{
		DiagMsg: sockInfo,
	}
	for _, a := range attrs {
		switch a.Attr.Type {
		case UNIX_DIAG_NAME:
			name := string(a.Value[:a.Attr.Len])
			info.Name = &name
		case UNIX_DIAG_PEER:
			peer := native.Uint32(a.Value)
			info.Peer = &peer
		case UNIX_DIAG_RQLEN:
			info.Queue = &QueueInfo{
				RQueue: native.Uint32(a.Value[:4]),
				WQueue: native.Uint32(a.Value[4:]),
			}
			// default:
			// 	fmt.Println("unknown unix attribute type", a.Attr.Type, "with data", a.Value)
		}
	}

	return info, nil
}
