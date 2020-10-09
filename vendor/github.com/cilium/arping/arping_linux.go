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

func (r *requester) receive() (arpDatagram, time.Time, error) {
	buffer := make([]byte, 128)
	n, _, err := syscall.Recvfrom(r.sock, buffer, 0)
	if err != nil {
		return arpDatagram{}, time.Now(), err
	}
	// skip 14 bytes ethernet header
	return parseArpDatagram(buffer[14:n]), time.Now(), nil
}

func (r *requester) deinitialize() error {
	return syscall.Close(r.sock)
}
