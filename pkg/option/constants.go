// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

const (
	TCP_FIN = uint8(0x01)
	TCP_SYN = uint8(0x02)
	TCP_RST = uint8(0x04)
	TCP_PSH = uint8(0x08)
	TCP_ACK = uint8(0x10)
	TCP_URG = uint8(0x20)
	TCP_ECE = uint8(0x40)
	TCP_CWR = uint8(0x80)
)

var (
	TCPFlags = map[string]uint8{
		"none": uint8(0x00),
		"all":  uint8(0xFF),
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
