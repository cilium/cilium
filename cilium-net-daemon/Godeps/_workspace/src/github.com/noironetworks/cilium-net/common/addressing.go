package common

import (
	"net"
)

// Default addressing schema
//
// cluster:		    beef:beef:beef:beef::/64
// loadbalancer:	beef:beef:beef:beef:<lb>::/80
// node:		    beef:beef:beef:beef:<lb>:<node>:<node>:/112
// lxc:			    beef:beef:beef:beef:<lb>:<node>:<node>:<lxc>/128

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

func BuildEndpointAddress(nodeAddr net.IP, v4Addr net.IP) net.IP {

	// beef:beef:beef:beef:1::1.0.0.2
	return net.ParseIP(nodeAddr.String() + v4Addr.String())
}

func dupIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}
