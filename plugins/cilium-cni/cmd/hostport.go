// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/plugins/cilium-cni/types"
)

type hostPortKey struct {
	port     uint16
	protocol string
	address  netip.Addr
}

func validateHostPorts(mappings []types.PortMapping) error {
	wanted := make([]hostPortKey, 0, len(mappings))
	for _, mapping := range mappings {
		if mapping.HostPort < 1 || mapping.HostPort > 65535 {
			return fmt.Errorf("invalid hostPort %d", mapping.HostPort)
		}

		protocol := strings.ToLower(mapping.Protocol)
		if protocol == "" {
			protocol = "tcp"
		}
		if protocol != "tcp" && protocol != "udp" {
			return fmt.Errorf("unsupported hostPort protocol %q", mapping.Protocol)
		}

		var address netip.Addr
		if mapping.HostIP != "" {
			var err error
			address, err = netip.ParseAddr(mapping.HostIP)
			if err != nil {
				return fmt.Errorf("invalid hostIP %q: %w", mapping.HostIP, err)
			}
		}
		wanted = append(wanted, hostPortKey{
			port: uint16(mapping.HostPort), protocol: protocol, address: address,
		})
	}
	if len(wanted) == 0 {
		return nil
	}
	diag, err := newSocketDiag()
	if err != nil {
		return fmt.Errorf("opening host SOCK_DIAG socket: %w", err)
	}
	defer diag.Close()

	queried := make(map[string]struct{})
	for _, mapping := range wanted {
		queryKey := fmt.Sprintf("%s/%d/%s", mapping.protocol, mapping.port,
			mapping.address)
		if _, ok := queried[queryKey]; ok {
			continue
		}
		queried[queryKey] = struct{}{}

		for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
			conflict, err := diag.findPort(mapping.protocol, family,
				mapping.port, mapping.address)
			if err != nil {
				return fmt.Errorf("querying host %s port %d with SOCK_DIAG: %w",
					mapping.protocol, mapping.port, err)
			}
			if conflict {
				return fmt.Errorf("hostPort %s/%d is already in use",
					mapping.protocol, mapping.port)
			}
		}
	}
	return nil
}

type socketDiag struct {
	fd  int
	seq uint32
}

func newSocketDiag() (*socketDiag, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_INET_DIAG)
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &socketDiag{fd: fd}, nil
}

func (s *socketDiag) Close() error {
	return unix.Close(s.fd)
}

func (s *socketDiag) findPort(protocol string, family uint8, port uint16,
	requestedIP netip.Addr,
) (bool, error) {
	proto := uint8(unix.IPPROTO_TCP)
	states := uint32(1 << 10) // TCP_LISTEN
	if protocol == "udp" {
		proto = unix.IPPROTO_UDP
		states = 0xfff
	}

	request := make([]byte, 16+56)
	binary.NativeEndian.PutUint32(request[0:4], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:6], unix.SOCK_DIAG_BY_FAMILY)
	binary.NativeEndian.PutUint16(request[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	s.seq++
	binary.NativeEndian.PutUint32(request[8:12], s.seq)
	request[16] = family
	request[17] = proto
	request[18] = 1 << (6 - 1) // INET_DIAG_TCLASS also requests INET_DIAG_SKV6ONLY.
	binary.NativeEndian.PutUint32(request[20:24], states)
	binary.BigEndian.PutUint16(request[24:26], port)
	if err := unix.Sendto(s.fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return false, err
	}

	buffer := make([]byte, 64*1024)
	for {
		n, _, err := unix.Recvfrom(s.fd, buffer, 0)
		if err != nil {
			return false, err
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			return false, err
		}
		done := false
		for _, message := range messages {
			if message.Header.Seq != s.seq {
				continue
			}
			if message.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
				return false, fmt.Errorf("SOCK_DIAG dump interrupted: %w", unix.EINTR)
			}
			switch message.Header.Type {
			case unix.NLMSG_DONE:
				if len(message.Data) >= 4 {
					code := int32(binary.NativeEndian.Uint32(message.Data[:4]))
					if code != 0 {
						return false, unix.Errno(-code)
					}
				}
				done = true
			case unix.NLMSG_ERROR:
				if len(message.Data) < 4 {
					return false, fmt.Errorf("short SOCK_DIAG error response")
				}
				code := int32(binary.NativeEndian.Uint32(message.Data[:4]))
				if family == unix.AF_INET6 && code == -int32(unix.EAFNOSUPPORT) {
					return false, nil
				}
				if code != 0 {
					return false, unix.Errno(-code)
				}
			case unix.SOCK_DIAG_BY_FAMILY:
				if len(message.Data) < 72 {
					return false, fmt.Errorf("short SOCK_DIAG socket response")
				}
				var address netip.Addr
				if family == unix.AF_INET {
					var bytes [4]byte
					copy(bytes[:], message.Data[8:12])
					address = netip.AddrFrom4(bytes)
				} else {
					var bytes [16]byte
					copy(bytes[:], message.Data[8:24])
					address = netip.AddrFrom16(bytes)
				}
				address = address.Unmap()
				ipv6Only := false
				for attrs := message.Data[72:]; len(attrs) >= 4; {
					length := int(binary.NativeEndian.Uint16(attrs[:2]))
					if length < 4 || length > len(attrs) {
						return false, fmt.Errorf("invalid SOCK_DIAG attribute length")
					}
					if binary.NativeEndian.Uint16(attrs[2:4]) == 11 && length >= 5 {
						ipv6Only = attrs[4] != 0 // INET_DIAG_SKV6ONLY
					}
					aligned := (length + 3) &^ 3
					if aligned > len(attrs) {
						break
					}
					attrs = attrs[aligned:]
				}
				if socketAddressesConflict(address, requestedIP, ipv6Only) {
					return true, nil
				}
			}
		}
		if done {
			return false, nil
		}
	}
}

func socketAddressesConflict(socketIP, requestedIP netip.Addr, ipv6Only bool) bool {
	if !requestedIP.IsValid() {
		return true
	}
	socketIP, requestedIP = socketIP.Unmap(), requestedIP.Unmap()
	if socketIP.Is4() != requestedIP.Is4() {
		return socketIP.Is6() && socketIP.IsUnspecified() && requestedIP.Is4() && !ipv6Only
	}
	return requestedIP.IsUnspecified() || socketIP.IsUnspecified() || socketIP == requestedIP
}
