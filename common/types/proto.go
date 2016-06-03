package types

import (
	"strconv"
)

var protoNames = map[int]string{
	1:  "ICMP",
	6:  "TCP",
	17: "UDP",
	58: "ICMPv6",
}

type U8proto uint8

func (p *U8proto) String() string {
	proto := int(*p)

	if _, ok := protoNames[proto]; ok {
		return protoNames[proto]
	} else {
		return strconv.Itoa(proto)
	}
}
