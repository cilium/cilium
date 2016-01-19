package common

import (
	"encoding/binary"
	"net"
)

func ValidEndpointAddress(addr net.IP) bool {
	switch len(addr) {
	case net.IPv4len:
		// Not supported yet
		return false
	case net.IPv6len:
		// node id may not be 0
		if addr[10] == 0 && addr[11] == 0 && addr[12] == 0 && addr[13] == 0 {
			return false
		}

		// endpoint id may not be 0
		if addr[14] == 0 && addr[15] == 0 {
			return false
		}
	}

	return true
}

func ValidNodeAddress(addr net.IP) bool {
	switch len(addr) {
	case net.IPv4len:
		// Not supported yet
		return false
	case net.IPv6len:
		// node id may not be 0
		if addr[10] == 0 && addr[11] == 0 && addr[12] == 0 && addr[13] == 0 {
			return false
		}

		// node address must contain 0 suffix
		if addr[14] != 0 || addr[15] != 0 {
			return false
		}
	}

	return true
}

func MapEndpointToNode(epAddr net.IP) net.IP {
	switch len(epAddr) {
	case net.IPv4len:
	// Not supported yet
	case net.IPv6len:
		nodeAddr := dupIP(epAddr)
		nodeAddr[14] = 0
		nodeAddr[15] = 0
		return nodeAddr
	}

	return nil
}

func Build4to6EndpointAddress(nodeAddr net.IP, v4Addr net.IP) net.IP {
	// beef:beef:beef:beef:1:0:[1.0.0.2]
	if len(nodeAddr) == net.IPv6len && len(v4Addr) == net.IPv4len {
		addr := dupIP(nodeAddr)
		copy(addr[12:], v4Addr)
		return addr
	}
	return nil
}

func EndpointID(epAddr net.IP) int {
	return int(binary.BigEndian.Uint16(epAddr[14:]))
}

func dupIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}
