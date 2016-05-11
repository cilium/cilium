package common

import (
	"encoding/binary"
	"net"
)

// ValidEndpointAddress checks if addr is a valid endpoint address. To be valid must obey
// to the following rules:
// - Be an IPv6 address
// - Node ID, bits from 112 to 120, must be different than 0
// - Endpoint ID, bits from 120 to 128, must be different than 0
func ValidEndpointAddress(addr net.IP) bool {
	switch len(addr) {
	case net.IPv4len:
		// Not supported yet
		return false
	case net.IPv6len:
		// If addr with NodeIPv6Mask is equal to addr means that have zeros from
		// 112 to 128.
		return !addr.Mask(NodeIPv6Mask).Equal(addr)
	}

	return true
}

// ValidNodeAddress checks if addr is a valid node address. To be valid must obey to the
// following rules:
// - Be an IPv6 address
// - Node ID, bits from 112 to 120, must be different than 0
// - Endpoint ID, bits from 120 to 128, must be equal to 0
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

		// lxc address must contain 0 suffix
		if addr[14] != 0 || addr[15] != 0 {
			return false
		}
	}

	return true
}

// MapEndpointToNode returns a copy of epAddr with endpoint ID, the last 2 bytes of the
// IPv6, set to 0.
func MapEndpointToNode(epAddr net.IP) net.IP {
	switch len(epAddr) {
	case net.IPv4len:
	// Not supported yet
	case net.IPv6len:
		nodeAddr := DupIP(epAddr)
		nodeAddr[14] = 0
		nodeAddr[15] = 0
		return nodeAddr
	}

	return nil
}

// Build4to6EndpointAddress returns a valid IPv6 endpoint address from the v4Addr. The
// returned IPv6 address will have the 2 last octets of v4Addr set as endpoint ID, the
// last 2 bytes returned address.
func Build4to6EndpointAddress(nodeAddr net.IP, v4Addr net.IP) net.IP {
	// beef:beef:beef:beef:1:0:[1.0.0.2]
	if len(nodeAddr) == net.IPv6len && len(v4Addr) == net.IPv4len {
		addr := DupIP(nodeAddr)
		copy(addr[14:], v4Addr[2:])
		return addr
	}
	return nil
}

// NodeAddr2ID returns an ID from the nodeAddr.
func NodeAddr2ID(nodeAddr net.IP) uint32 {
	if len(nodeAddr) == net.IPv6len {
		return binary.BigEndian.Uint32(nodeAddr[10:14])
	}
	return 0
}

// EndpointAddr2ID returns an endpoint ID from the endpointAddr.
func EndpointAddr2ID(endpointAddr net.IP) uint16 {
	if len(endpointAddr) == net.IPv6len {
		return binary.BigEndian.Uint16(endpointAddr[14:])
	}
	return 0
}

// DupIP returns a deep copy of ip.
func DupIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

// NextNetwork returns the next network for the given IPNet.
// Example:
// NextNetwork(::dead/120) // ::df00, since the network of ::dead/120 is ::de00, the next
// network is df00.
// NextNetwork(ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128) // ::, we always overflow to
// the next network.
func NextNetwork(ip net.IPNet) net.IP {
	trimmedIP := ip.IP.Mask(ip.Mask)
	ones, _ := ip.Mask.Size()
	// ffff:ffff:ffff:ffff:ffff:fead:ffff:ffff
	//                          ^^ -> element 10
	elem := (ones - 1) / 8
	pos := uint16(0x01)
	// ffff:ffff:ffff:ffff:ffff:fead:ffff:ffff
	// ......: 1111 1110 1010 1101: .....
	//         7654 3210 7654 3210
	//           ^ -> position 5
	pos <<= uint8((8 - (ones % 8)) % 8)
	l := len(trimmedIP)
	res := make(net.IP, l)
	carry := uint16(0)
	for i := l - 1; i >= 0; i-- {
		tmpRes := uint16(0)
		if elem == i {
			tmpRes = uint16(trimmedIP[i]) + pos + carry
		} else {
			tmpRes = uint16(trimmedIP[i]) + carry
		}
		res[i] = byte(tmpRes)
		carry = tmpRes >> 8
	}
	return res
}
