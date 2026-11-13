// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
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
		return validateHostPortsProc(wanted)
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
				return validateHostPortsProc(wanted)
			}
			if conflict {
				return fmt.Errorf("hostPort %s/%d is already in use",
					mapping.protocol, mapping.port)
			}
		}
	}
	return nil
}

// Proc does not report IPV6_V6ONLY, so IPv6 wildcard listeners are
// conservatively treated as dual-stack listeners.
func validateHostPortsProc(wanted []hostPortKey) error {
	for _, protocol := range []string{"tcp", "udp"} {
		for _, family := range []string{"", "6"} {
			// thread-self follows the thread switched by netns.Do; /proc/net
			// follows the process leader and would inspect the wrong namespace.
			path := "/proc/thread-self/net/" + protocol + family
			f, err := os.Open(path)
			if err != nil {
				if family == "6" && errors.Is(err, os.ErrNotExist) {
					continue
				}
				return fmt.Errorf("reading host sockets from %s: %w", path, err)
			}

			scanner := bufio.NewScanner(f)
			if scanner.Scan() {
				for scanner.Scan() {
					fields := strings.Fields(scanner.Text())
					if len(fields) < 4 {
						continue
					}

					localIP, localPort, err := parseProcSocketAddress(fields[1])
					if err != nil {
						continue
					}
					if protocol == "tcp" && fields[3] != "0A" {
						continue
					}
					localIP = localIP.Unmap()
					for _, mapping := range wanted {
						if mapping.protocol == protocol &&
							mapping.port == uint16(localPort) &&
							socketAddressesConflict(localIP, mapping.address, false) {
							f.Close()
							return fmt.Errorf("hostPort %s/%d is already in use",
								mapping.protocol, mapping.port)
						}
					}
				}
			}
			scanErr := scanner.Err()
			f.Close()
			if scanErr != nil {
				return fmt.Errorf("reading host sockets from %s: %w", path, scanErr)
			}
		}
	}
	return nil
}

func parseProcSocketAddress(value string) (netip.Addr, int, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return netip.Addr{}, 0, fmt.Errorf("invalid socket address %q", value)
	}
	// Proc prints each address word in native byte order.
	if len(parts[0]) != 8 && len(parts[0]) != 32 {
		return netip.Addr{}, 0, fmt.Errorf("invalid socket address %q", value)
	}
	address := make([]byte, len(parts[0])/2)
	for offset := 0; offset < len(address); offset += 4 {
		word, err := strconv.ParseUint(parts[0][offset*2:offset*2+8], 16, 32)
		if err != nil {
			return netip.Addr{}, 0, err
		}
		binary.NativeEndian.PutUint32(address[offset:offset+4], uint32(word))
	}
	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	var ip netip.Addr
	if len(address) == 4 {
		var bytes [4]byte
		copy(bytes[:], address)
		ip = netip.AddrFrom4(bytes)
	} else {
		var bytes [16]byte
		copy(bytes[:], address)
		ip = netip.AddrFrom16(bytes)
	}
	return ip, int(port), nil
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

func validateHostPortNodePortOverlap(mappings []types.PortMapping, config map[string]any) error {
	if len(mappings) == 0 {
		return nil
	}
	minValue, haveMin := config["NodePortMin"]
	maxValue, haveMax := config["NodePortMax"]
	if !haveMin && !haveMax {
		// Older agents do not expose their effective NodePort range.
		return nil
	}
	// The API client's JSON consumer preserves numeric values as json.Number.
	minNumber, minOK := minValue.(json.Number)
	maxNumber, maxOK := maxValue.(json.Number)
	min, minErr := minNumber.Int64()
	max, maxErr := maxNumber.Int64()
	if !minOK || !maxOK || minErr != nil || maxErr != nil ||
		min < 1 || max > 65535 || min > max {
		return fmt.Errorf("invalid NodePort range in agent configuration: %v-%v", minValue, maxValue)
	}
	for _, mapping := range mappings {
		if mapping.HostPort >= int(min) && mapping.HostPort <= int(max) {
			return fmt.Errorf("hostPort %d overlaps with the configured NodePort range %d-%d",
				mapping.HostPort, int(min), int(max))
		}
	}
	return nil
}
