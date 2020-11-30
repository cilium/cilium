package arping

import (
	"net"
	"syscall"
	"time"
)

type requester struct {
	sock       int
	toSockaddr syscall.SockaddrLinklayer
}

func initialize(iface net.Interface) (*requester, error) {
	toSockaddr := syscall.SockaddrLinklayer{Ifindex: iface.Index}

	// 1544 = htons(ETH_P_ARP)
	const proto = 1544
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, proto)
	if err != nil {
		return nil, err
	}

	return &requester{
		sock:       sock,
		toSockaddr: toSockaddr,
	}, nil
}

func (r *requester) send(request arpDatagram) (time.Time, error) {
	return time.Now(), syscall.Sendto(r.sock, request.MarshalWithEthernetHeader(), 0, &r.toSockaddr)
}

func FD_SET(p *syscall.FdSet, i int) {
	p.Bits[i/64] |= 1 << (uint(i) % 64)
}

func (r *requester) receive(timeout time.Duration) (arpDatagram, time.Time, error) {
	fds := &syscall.FdSet{}
	FD_SET(fds, r.sock)
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	var err error
	var ready int
	if ready, err = syscall.Select(r.sock+1, fds, nil, nil, &tv); err == nil && ready == 1 {
		buffer := make([]byte, 128)
		var n int
		n, _, err = syscall.Recvfrom(r.sock, buffer, 0)
		if err == nil {
			// Need at least 14 bytes Eth header + 28 bytes of ARP datagram
			if n < 14+28 {
				return arpDatagram{}, time.Now(), ErrSize
			}
			// skip 14 bytes ethernet header
			return parseArpDatagram(buffer[14:n]), time.Now(), nil
		}
	} else if err == nil && ready == 0 {
		return arpDatagram{}, time.Now(), ErrTimeout
	}
	return arpDatagram{}, time.Now(), err
}

func (r *requester) deinitialize() error {
	return syscall.Close(r.sock)
}
