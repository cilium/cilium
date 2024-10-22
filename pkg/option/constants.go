// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

const (
	// TCP_FIN, ... from <linux/tcp.h> (host byte-order)
	TCP_FIN = uint16(0x0001)
	TCP_SYN = uint16(0x0002)
	TCP_RST = uint16(0x0004)
	TCP_PSH = uint16(0x0008)
	TCP_ACK = uint16(0x0010)
	TCP_URG = uint16(0x0020)
	TCP_ECE = uint16(0x0040)
	TCP_CWR = uint16(0x0080)
)

var (
	TCPFlags = map[string]uint16{
		"none": uint16(0x0000),
		"all":  uint16(0x00FF),
		"fin":  TCP_FIN,
		"syn":  TCP_SYN,
		"rst":  TCP_RST,
		"psh":  TCP_PSH,
		"ack":  TCP_ACK,
		"urg":  TCP_URG,
		"ece":  TCP_ECE,
		"cwr":  TCP_CWR,
	}
)

type BPFClockSource int

const (
	ClockSourceKtime BPFClockSource = iota
	ClockSourceJiffies
)

const HostExtensionMKE = 0x1bda7a
