package common

import (
	"net"
)

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
