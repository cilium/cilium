package types

import (
	"net"
)

// binary representation for encoding in binary structs
type IPv6 [16]byte

func (v6 IPv6) IP() net.IP {
	return v6[:]
}

func (v6 IPv6) String() string {
	return v6.IP().String()
}
