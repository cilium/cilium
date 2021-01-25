// Copyright 2020-2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package filters

import (
	"github.com/cilium/cilium/api/v1/flow"
)

// FlowFilterFunc is a function to filter on a condition in a flow. It returns
// true if the condition is true.
type FlowFilterFunc func(flow *flow.Flow) bool

// And returns true if all FlowFilterFunc return true
func And(funcs ...FlowFilterFunc) FlowFilterFunc {
	return func(flow *flow.Flow) bool {
		for _, f := range funcs {
			if !f(flow) {
				return false
			}
		}
		return true
	}
}

// Or returns true if any FlowFilterFunc return true
func Or(funcs ...FlowFilterFunc) FlowFilterFunc {
	return func(flow *flow.Flow) bool {
		for _, f := range funcs {
			if f(flow) {
				return true
			}
		}
		return false
	}
}

// Drop matches on drops
func Drop() FlowFilterFunc {
	return func(flow *flow.Flow) bool {
		r := flow.GetDropReason()
		return r != uint32(0)
	}
}

// ICMP matches on ICMP messages of the specified type
func ICMP(typ uint32) FlowFilterFunc {
	return func(flow *flow.Flow) bool {
		l4 := flow.GetL4()
		if l4 == nil {
			return false
		}

		icmp := l4.GetICMPv4()
		if icmp == nil {
			return false
		}

		if icmp.Type != typ {
			return false
		}

		return true
	}
}

// UDP matches on UDP packets with the specified source and destination ports
func UDP(srcPort, dstPort int) FlowFilterFunc {
	return func(flow *flow.Flow) bool {
		l4 := flow.GetL4()
		if l4 == nil {
			return false
		}

		udp := l4.GetUDP()
		if udp == nil {
			return false
		}

		if srcPort != 0 && udp.SourcePort != uint32(srcPort) {
			return false
		}

		if dstPort != 0 && udp.DestinationPort != uint32(dstPort) {
			return false
		}

		return true
	}
}

// TCPFlags matches on TCP packets with the specified TCP flags
func TCPFlags(syn, ack, fin, rst bool) FlowFilterFunc {
	return func(flow *flow.Flow) bool {
		l4 := flow.GetL4()
		if l4 == nil {
			return false
		}

		tcp := l4.GetTCP()
		if tcp == nil || tcp.Flags == nil {
			return false
		}

		if tcp.Flags.SYN != syn || tcp.Flags.ACK != ack || tcp.Flags.FIN != fin || tcp.Flags.RST != rst {
			return false
		}

		return true
	}
}

// FIN matches on TCP packets with FIN+ACK flags
func FIN() FlowFilterFunc {
	return TCPFlags(false, true, true, false)
}

// RST matches on TCP packets with RST+ACK flags
func RST() FlowFilterFunc {
	return TCPFlags(false, true, false, true)
}

// SYNACK matches on TCP packets with SYN+ACK flags
func SYNACK() FlowFilterFunc {
	return TCPFlags(true, true, false, false)
}

// SYN matches on TCP packets with SYN flag
func SYN() FlowFilterFunc {
	return TCPFlags(true, false, false, false)
}

// IP matches on IP packets with specified source and destination IP
func IP(srcIP, dstIP string) FlowFilterFunc {
	return func(flow *flow.Flow) bool {
		ip := flow.GetIP()
		if ip == nil {
			return false
		}
		if srcIP != "" && ip.Source != srcIP {
			return false
		}

		if dstIP != "" && ip.Destination != dstIP {
			return false
		}

		return true
	}
}

// TCP matches on TCP packets with the specified source and destination ports
func TCP(srcPort, dstPort int) FlowFilterFunc {
	return func(flow *flow.Flow) bool {
		l4 := flow.GetL4()
		if l4 == nil {
			return false
		}

		tcp := l4.GetTCP()
		if tcp == nil {
			return false
		}

		if srcPort != 0 && tcp.SourcePort != uint32(srcPort) {
			return false
		}

		if dstPort != 0 && tcp.DestinationPort != uint32(dstPort) {
			return false
		}

		return true
	}
}
