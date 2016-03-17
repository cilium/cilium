package types

import (
	"fmt"
	"net"
)

type MAC net.HardwareAddr

func (m MAC) String() string {
	return net.HardwareAddr(m).String()
}

func (m MAC) Uint64() (uint64, error) {
	if len(m) != 6 {
		return 0, fmt.Errorf("Invalid MAC address %s", m.String())
	}

	return uint64(uint64(m[5])<<40 | uint64(m[4])<<32 | uint64(m[3])<<24 |
		uint64(m[2])<<16 | uint64(m[1])<<8 | uint64(m[0])), nil
}
