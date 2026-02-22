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
	// ANY represents protocols with transport-layer ports (TCP, UDP, SCTP).
	ANY    U8proto = 0
	ICMP   U8proto = 1
	IGMP   U8proto = 2
	IPIP   U8proto = 4  // IP-in-IP Encapsulation (RFC 2003)
	TCP    U8proto = 6
	UDP    U8proto = 17
	IPv6   U8proto = 41 // IPv6 Encapsulation (6in4, RFC 4213)
	GRE    U8proto = 47 // Generic Routing Encapsulation (RFC 2784)
	ESP    U8proto = 50 // Encapsulating Security Payload (RFC 4303)
	AH     U8proto = 51 // Authentication Header (RFC 4302)
	ICMPv6 U8proto = 58
	VRRP   U8proto = 112
	SCTP   U8proto = 132
)

var protoNames = map[U8proto]string{
	0:   "ANY",
	1:   "ICMP",
	2:   "IGMP",
	4:   "IPIP",
	6:   "TCP",
	17:  "UDP",
	41:  "IPv6",
	47:  "GRE",
	50:  "ESP",
	51:  "AH",
	58:  "ICMPv6",
	112: "VRRP",
	132: "SCTP",
}

var ProtoIDs = map[string]U8proto{
	"all":    0,
	"any":    0,
	"none":   0,
	"icmp":   1,
	"igmp":   2,
	"ipip":   4,
	"tcp":    6,
	"udp":    17,
	"ipv6":   41,
	"gre":    47,
	"esp":    50,
	"ah":     51,
	"icmpv6": 58,
	"vrrp":   112,
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
