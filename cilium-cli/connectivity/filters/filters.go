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
	"fmt"
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

// FlowFilterFunc is a function to filter on a condition in a flow. It returns
// true if the condition is true.
type FlowFilterFunc func(flow *flowpb.Flow) bool

type FlowFilterImplementation interface {
	Match(flow *flowpb.Flow) bool
	String() string
}

type FlowRequirement struct {
	Filter FlowFilterImplementation
	Msg    string
}

type FlowSetRequirement struct {
	First  FlowRequirement
	Middle []FlowRequirement
	Last   FlowRequirement
	Except []FlowRequirement
}

type andFilter struct {
	filters []FlowFilterImplementation
}

func (a *andFilter) Match(flow *flowpb.Flow) bool {
	for _, f := range a.filters {
		if !f.Match(flow) {
			return false
		}
	}
	return true
}

func (a *andFilter) String() string {
	var s []string
	for _, f := range a.filters {
		s = append(s, f.String())
	}
	return "and(" + strings.Join(s, ",") + ")"
}

// And returns true if all filters return true
func And(filters ...FlowFilterImplementation) FlowFilterImplementation {
	return &andFilter{
		filters: filters,
	}
}

type orFilter struct {
	filters []FlowFilterImplementation
}

func (o *orFilter) Match(flow *flowpb.Flow) bool {
	for _, f := range o.filters {
		if f.Match(flow) {
			return true
		}
	}
	return false
}

func (o *orFilter) String() string {
	var s []string
	for _, f := range o.filters {
		s = append(s, f.String())
	}
	return "or(" + strings.Join(s, ",") + ")"
}

// Or returns true if any FlowFilterImplementation return true
func Or(filters ...FlowFilterImplementation) FlowFilterImplementation {
	return &orFilter{filters: filters}
}

type dropFilter struct{}

func (d *dropFilter) Match(flow *flowpb.Flow) bool {
	return flow.GetDropReasonDesc() != flowpb.DropReason_DROP_REASON_UNKNOWN
}

func (d *dropFilter) String() string {
	return "drop"
}

// Drop matches on drops
func Drop() FlowFilterImplementation {
	return &dropFilter{}
}

type icmpFilter struct {
	typ uint32
}

func (i *icmpFilter) Match(flow *flowpb.Flow) bool {
	l4 := flow.GetL4()
	if l4 == nil {
		return false
	}

	icmp := l4.GetICMPv4()
	if icmp == nil {
		return false
	}

	if icmp.Type != i.typ {
		return false
	}

	return true
}

func (i *icmpFilter) String() string {
	return fmt.Sprintf("icmp(%d)", i.typ)
}

// ICMP matches on ICMP messages of the specified type
func ICMP(typ uint32) FlowFilterImplementation {
	return &icmpFilter{typ: typ}
}

type icmpv6Filter struct {
	typ uint32
}

func (i *icmpv6Filter) Match(flow *flowpb.Flow) bool {
	l4 := flow.GetL4()
	if l4 == nil {
		return false
	}

	icmpv6 := l4.GetICMPv6()
	if icmpv6 == nil {
		return false
	}

	if icmpv6.Type != i.typ {
		return false
	}

	return true
}

func (i *icmpv6Filter) String() string {
	return fmt.Sprintf("icmpv6(%d)", i.typ)
}

// ICMPv6 matches on ICMPv6 messages of the specified type
func ICMPv6(typ uint32) FlowFilterImplementation {
	return &icmpv6Filter{typ: typ}
}

type udpFilter struct {
	srcPort int
	dstPort int
}

func (u *udpFilter) Match(flow *flowpb.Flow) bool {
	l4 := flow.GetL4()
	if l4 == nil {
		return false
	}

	udp := l4.GetUDP()
	if udp == nil {
		return false
	}

	if u.srcPort != 0 && udp.SourcePort != uint32(u.srcPort) {
		return false
	}

	if u.dstPort != 0 && udp.DestinationPort != uint32(u.dstPort) {
		return false
	}

	return true
}

func (u *udpFilter) String() string {
	var s []string
	if u.srcPort != 0 {
		s = append(s, fmt.Sprintf("srcPort=%d", u.srcPort))
	}
	if u.dstPort != 0 {
		s = append(s, fmt.Sprintf("dstPort=%d", u.dstPort))
	}
	return "udp(" + strings.Join(s, ",") + ")"
}

// UDP matches on UDP packets with the specified source and destination ports
func UDP(srcPort, dstPort int) FlowFilterImplementation {
	return &udpFilter{srcPort: srcPort, dstPort: dstPort}
}

type tcpFlagsFilter struct {
	syn, ack, fin, rst bool
}

func (t *tcpFlagsFilter) Match(flow *flowpb.Flow) bool {
	l4 := flow.GetL4()
	if l4 == nil {
		return false
	}

	tcp := l4.GetTCP()
	if tcp == nil || tcp.Flags == nil {
		return false
	}

	if tcp.Flags.SYN != t.syn || tcp.Flags.ACK != t.ack || tcp.Flags.FIN != t.fin || tcp.Flags.RST != t.rst {
		return false
	}

	return true
}

func (t *tcpFlagsFilter) String() string {
	var s []string
	if t.syn {
		s = append(s, "syn")
	}
	if t.ack {
		s = append(s, "ack")
	}
	if t.fin {
		s = append(s, "fin")
	}
	if t.rst {
		s = append(s, "rst")
	}
	return "tcpflags(" + strings.Join(s, ",") + ")"
}

// TCPFlags matches on TCP packets with the specified TCP flags
func TCPFlags(syn, ack, fin, rst bool) FlowFilterImplementation {
	return &tcpFlagsFilter{syn: syn, ack: ack, fin: fin, rst: rst}
}

// FIN matches on TCP packets with FIN+ACK flags
func FIN() FlowFilterImplementation {
	return TCPFlags(false, true, true, false)
}

// RST matches on TCP packets with RST+ACK flags
func RST() FlowFilterImplementation {
	return TCPFlags(false, true, false, true)
}

// SYNACK matches on TCP packets with SYN+ACK flags
func SYNACK() FlowFilterImplementation {
	return TCPFlags(true, true, false, false)
}

// SYN matches on TCP packets with SYN flag
func SYN() FlowFilterImplementation {
	return TCPFlags(true, false, false, false)
}

type ipFilter struct {
	srcIP string
	dstIP string
}

func (i *ipFilter) Match(flow *flowpb.Flow) bool {
	ip := flow.GetIP()
	if ip == nil {
		return false
	}
	if i.srcIP != "" && ip.Source != i.srcIP {
		return false
	}

	if i.dstIP != "" && ip.Destination != i.dstIP {
		return false
	}

	return true
}

func (i *ipFilter) String() string {
	var s []string
	if i.srcIP != "" {
		s = append(s, "src="+i.srcIP)
	}
	if i.dstIP != "" {
		s = append(s, "dst="+i.dstIP)
	}
	return "ip(" + strings.Join(s, ",") + ")"
}

// IP matches on IP packets with specified source and destination IP
func IP(srcIP, dstIP string) FlowFilterImplementation {
	return &ipFilter{srcIP: srcIP, dstIP: dstIP}
}

type tcpFilter struct {
	srcPort int
	dstPort int
}

func (t *tcpFilter) Match(flow *flowpb.Flow) bool {
	l4 := flow.GetL4()
	if l4 == nil {
		return false
	}

	tcp := l4.GetTCP()
	if tcp == nil {
		return false
	}

	if t.srcPort != 0 && tcp.SourcePort != uint32(t.srcPort) {
		return false
	}

	if t.dstPort != 0 && tcp.DestinationPort != uint32(t.dstPort) {
		return false
	}

	return true
}

func (t *tcpFilter) String() string {
	var s []string
	if t.srcPort != 0 {
		s = append(s, fmt.Sprintf("srcPort=%d", t.srcPort))
	}
	if t.dstPort != 0 {
		s = append(s, fmt.Sprintf("dstPort=%d", t.dstPort))
	}
	return "tcp(" + strings.Join(s, ",") + ")"
}

// TCP matches on TCP packets with the specified source and destination ports
func TCP(srcPort, dstPort int) FlowFilterImplementation {
	return &tcpFilter{srcPort: srcPort, dstPort: dstPort}
}
