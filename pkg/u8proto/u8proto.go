// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package u8proto

import (
	"fmt"
	"strconv"
	"strings"
)

// These definitions must contain and be compatible with the string
// values defined for pkg/pollicy/api/L4Proto

const (
	// ANY represents all protocols.
	ANY    U8proto = 0
	ICMP   U8proto = 1
	TCP    U8proto = 6
	UDP    U8proto = 17
	ICMPv6 U8proto = 58
	SCTP   U8proto = 132
)

var protoNames = map[U8proto]string{
	0:   "ANY",
	1:   "ICMP",
	6:   "TCP",
	17:  "UDP",
	58:  "ICMPv6",
	132: "SCTP",
}

var ProtoIDs = map[string]U8proto{
	"all":    0,
	"any":    0,
	"none":   0,
	"icmp":   1,
	"tcp":    6,
	"udp":    17,
	"icmpv6": 58,
	"sctp":   132,
}

type U8proto uint8

func (p U8proto) String() string {
	if _, ok := protoNames[p]; ok {
		return protoNames[p]
	}
	return strconv.Itoa(int(p))
}

func ParseProtocol(proto string) (U8proto, error) {
	if u, ok := ProtoIDs[strings.ToLower(proto)]; ok {
		return u, nil
	}
	return 0, fmt.Errorf("unknown protocol '%s'", proto)
}

func FromNumber(proto uint8) (U8proto, error) {
	_, ok := protoNames[U8proto(proto)]
	if !ok {
		return 0, fmt.Errorf("unknown protocol %d", proto)
	}
	return U8proto(proto), nil
}
