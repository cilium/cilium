package common

import (
	"net"
)

// DupIP returns a deep copy of ip.
func DupIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}
