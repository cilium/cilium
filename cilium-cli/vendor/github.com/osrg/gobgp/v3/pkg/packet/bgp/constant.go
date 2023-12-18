// Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bgp

import (
	"strconv"
	"strings"
)

const AS_TRANS = 23456

const BGP_PORT = 179

//go:generate stringer -type=FSMState
type FSMState int

const (
	BGP_FSM_IDLE FSMState = iota
	BGP_FSM_CONNECT
	BGP_FSM_ACTIVE
	BGP_FSM_OPENSENT
	BGP_FSM_OPENCONFIRM
	BGP_FSM_ESTABLISHED
)

// partially taken from http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
type Protocol int

const (
	Unknown Protocol = iota
	ICMP             = 0x01
	IGMP             = 0x02
	TCP              = 0x06
	EGP              = 0x08
	IGP              = 0x09
	UDP              = 0x11
	RSVP             = 0x2e
	GRE              = 0x2f
	OSPF             = 0x59
	IPIP             = 0x5e
	PIM              = 0x67
	SCTP             = 0x84
)

var ProtocolNameMap = map[Protocol]string{
	Unknown: "unknown",
	ICMP:    "icmp",
	IGMP:    "igmp",
	TCP:     "tcp",
	EGP:     "egp",
	IGP:     "igp",
	UDP:     "udp",
	RSVP:    "rsvp",
	GRE:     "gre",
	OSPF:    "ospf",
	IPIP:    "ipip",
	PIM:     "pim",
	SCTP:    "sctp",
}

func (p Protocol) String() string {
	name, ok := ProtocolNameMap[p]
	if !ok {
		return strconv.Itoa(int(p))
	}
	return name
}

type TCPFlag int

const (
	_               TCPFlag = iota
	TCP_FLAG_FIN            = 0x01
	TCP_FLAG_SYN            = 0x02
	TCP_FLAG_RST            = 0x04
	TCP_FLAG_PUSH           = 0x08
	TCP_FLAG_ACK            = 0x10
	TCP_FLAG_URGENT         = 0x20
	TCP_FLAG_ECE            = 0x40
	TCP_FLAG_CWR            = 0x80
)

var TCPFlagNameMap = map[TCPFlag]string{
	TCP_FLAG_FIN:    "F",
	TCP_FLAG_SYN:    "S",
	TCP_FLAG_RST:    "R",
	TCP_FLAG_PUSH:   "P",
	TCP_FLAG_ACK:    "A",
	TCP_FLAG_URGENT: "U",
	TCP_FLAG_CWR:    "C",
	TCP_FLAG_ECE:    "E",
}

// Prepares a sorted list of flags because map iterations does not happen
// in a consistent order in Golang.
var TCPSortedFlags = []TCPFlag{
	TCP_FLAG_FIN,
	TCP_FLAG_SYN,
	TCP_FLAG_RST,
	TCP_FLAG_PUSH,
	TCP_FLAG_ACK,
	TCP_FLAG_URGENT,
	TCP_FLAG_ECE,
	TCP_FLAG_CWR,
}

func (f TCPFlag) String() string {
	flags := make([]string, 0, len(TCPSortedFlags))
	for _, v := range TCPSortedFlags {
		if f&v > 0 {
			flags = append(flags, TCPFlagNameMap[v])
		}
	}
	return strings.Join(flags, "")
}

type BitmaskFlagOp uint8

const (
	BITMASK_FLAG_OP_OR        BitmaskFlagOp = iota
	BITMASK_FLAG_OP_MATCH                   = 0x01
	BITMASK_FLAG_OP_NOT                     = 0x02
	BITMASK_FLAG_OP_NOT_MATCH               = 0x03
	BITMASK_FLAG_OP_AND                     = 0x40
	BITMASK_FLAG_OP_END                     = 0x80
)

var BitmaskFlagOpNameMap = map[BitmaskFlagOp]string{
	BITMASK_FLAG_OP_OR:    " ",
	BITMASK_FLAG_OP_AND:   "&",
	BITMASK_FLAG_OP_END:   "E",
	BITMASK_FLAG_OP_NOT:   "!",
	BITMASK_FLAG_OP_MATCH: "=",
}

// Note: Meaning of "" is different from that of the numeric operator because
// RFC5575 says if the Match bit in the bitmask operand is set, it should be
// "strictly" matching against the given value.
var BitmaskFlagOpValueMap = map[string]BitmaskFlagOp{
	" ":  BITMASK_FLAG_OP_OR,
	"":   BITMASK_FLAG_OP_OR,
	"==": BITMASK_FLAG_OP_MATCH,
	"=":  BITMASK_FLAG_OP_MATCH,
	"!":  BITMASK_FLAG_OP_NOT,
	"!=": BITMASK_FLAG_OP_NOT_MATCH,
	"=!": BITMASK_FLAG_OP_NOT_MATCH, // For the backward compatibility
	"&":  BITMASK_FLAG_OP_AND,
	"E":  BITMASK_FLAG_OP_END,
}

func (f BitmaskFlagOp) String() string {
	ops := make([]string, 0, 3)
	if f&BITMASK_FLAG_OP_AND > 0 {
		ops = append(ops, BitmaskFlagOpNameMap[BITMASK_FLAG_OP_AND])
	} else {
		ops = append(ops, BitmaskFlagOpNameMap[BITMASK_FLAG_OP_OR])
	}
	if f&BITMASK_FLAG_OP_NOT > 0 {
		ops = append(ops, BitmaskFlagOpNameMap[BITMASK_FLAG_OP_NOT])
	}
	if f&BITMASK_FLAG_OP_MATCH > 0 {
		ops = append(ops, BitmaskFlagOpNameMap[BITMASK_FLAG_OP_MATCH])
	}
	return strings.Join(ops, "")
}

type FragmentFlag int

const (
	FRAG_FLAG_NOT   FragmentFlag = iota
	FRAG_FLAG_DONT               = 0x01
	FRAG_FLAG_IS                 = 0x02
	FRAG_FLAG_FIRST              = 0x04
	FRAG_FLAG_LAST               = 0x08
)

var FragmentFlagNameMap = map[FragmentFlag]string{
	FRAG_FLAG_NOT:   "not-a-fragment",
	FRAG_FLAG_DONT:  "dont-fragment",
	FRAG_FLAG_IS:    "is-fragment",
	FRAG_FLAG_FIRST: "first-fragment",
	FRAG_FLAG_LAST:  "last-fragment",
}

// Prepares a sorted list of flags because map iterations does not happen
// in a consistent order in Golang.
var FragmentSortedFlags = []FragmentFlag{
	FRAG_FLAG_NOT,
	FRAG_FLAG_DONT,
	FRAG_FLAG_IS,
	FRAG_FLAG_FIRST,
	FRAG_FLAG_LAST,
}

func (f FragmentFlag) String() string {
	flags := make([]string, 0, len(FragmentSortedFlags))
	for _, v := range FragmentSortedFlags {
		if f&v > 0 {
			flags = append(flags, FragmentFlagNameMap[v])
		}
	}
	// Note: If multiple bits are set, joins them with "+".
	return strings.Join(flags, "+")
}

type DECNumOp uint8

const (
	DEC_NUM_OP_TRUE   DECNumOp = iota // true always with END bit set
	DEC_NUM_OP_EQ              = 0x01
	DEC_NUM_OP_GT              = 0x02
	DEC_NUM_OP_GT_EQ           = 0x03
	DEC_NUM_OP_LT              = 0x04
	DEC_NUM_OP_LT_EQ           = 0x05
	DEC_NUM_OP_NOT_EQ          = 0x06
	DEC_NUM_OP_FALSE           = 0x07 // false always with END bit set
	DEC_NUM_OP_OR              = 0x00
	DEC_NUM_OP_AND             = 0x40
	DEC_NUM_OP_END             = 0x80
)

var DECNumOpNameMap = map[DECNumOp]string{
	DEC_NUM_OP_TRUE:   "true",
	DEC_NUM_OP_EQ:     "==",
	DEC_NUM_OP_GT:     ">",
	DEC_NUM_OP_GT_EQ:  ">=",
	DEC_NUM_OP_LT:     "<",
	DEC_NUM_OP_LT_EQ:  "<=",
	DEC_NUM_OP_NOT_EQ: "!=",
	DEC_NUM_OP_FALSE:  "false",
	//DEC_NUM_OP_OR:   " ", // duplicate with DEC_NUM_OP_TRUE
	DEC_NUM_OP_AND: "&",
	DEC_NUM_OP_END: "E",
}

var DECNumOpValueMap = map[string]DECNumOp{
	"true":  DEC_NUM_OP_TRUE,
	"":      DEC_NUM_OP_EQ,
	"==":    DEC_NUM_OP_EQ,
	"=":     DEC_NUM_OP_EQ,
	">":     DEC_NUM_OP_GT,
	">=":    DEC_NUM_OP_GT_EQ,
	"<":     DEC_NUM_OP_LT,
	"<=":    DEC_NUM_OP_LT_EQ,
	"!=":    DEC_NUM_OP_NOT_EQ,
	"=!":    DEC_NUM_OP_NOT_EQ,
	"!":     DEC_NUM_OP_NOT_EQ,
	"false": DEC_NUM_OP_FALSE,
	" ":     DEC_NUM_OP_OR,
	"&":     DEC_NUM_OP_AND,
	"E":     DEC_NUM_OP_END,
}

func (f DECNumOp) String() string {
	ops := make([]string, 0)
	logicFlag := DECNumOp(f & 0xc0) // higher 2 bits
	if logicFlag&DEC_NUM_OP_AND > 0 {
		ops = append(ops, DECNumOpNameMap[DEC_NUM_OP_AND])
	} else {
		ops = append(ops, " ") // DEC_NUM_OP_OR
	}
	// Omits DEC_NUM_OP_END
	cmpFlag := DECNumOp(f & 0x7) // lower 3 bits
	for v, s := range DECNumOpNameMap {
		if cmpFlag == v {
			ops = append(ops, s)
			break
		}
	}
	return strings.Join(ops, "")
}

// Potentially taken from https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
type EthernetType int

const (
	IPv4            EthernetType = 0x0800
	ARP             EthernetType = 0x0806
	RARP            EthernetType = 0x8035
	VMTP            EthernetType = 0x805B
	APPLE_TALK      EthernetType = 0x809B
	AARP            EthernetType = 0x80F3
	IPX             EthernetType = 0x8137
	SNMP            EthernetType = 0x814C
	NET_BIOS        EthernetType = 0x8191
	XTP             EthernetType = 0x817D
	IPv6            EthernetType = 0x86DD
	PPPoE_DISCOVERY EthernetType = 0x8863
	PPPoE_SESSION   EthernetType = 0x8864
	LOOPBACK        EthernetType = 0x9000
)

var EthernetTypeNameMap = map[EthernetType]string{
	IPv4:            "ipv4",
	ARP:             "arp",
	RARP:            "rarp",
	VMTP:            "vmtp",
	APPLE_TALK:      "apple-talk",
	AARP:            "aarp",
	IPX:             "ipx",
	SNMP:            "snmp",
	NET_BIOS:        "net-bios",
	XTP:             "xtp",
	IPv6:            "ipv6",
	PPPoE_DISCOVERY: "pppoe-discovery",
	PPPoE_SESSION:   "pppoe-session",
	LOOPBACK:        "loopback",
}

func (t EthernetType) String() string {
	if name, ok := EthernetTypeNameMap[t]; ok {
		return name
	}
	return strconv.Itoa(int(t))
}
