// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package filters

import (
	"fmt"
	"math"
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

type portMap map[uint32]uint32

// FlowContext can carry state from one filter to another.
type FlowContext struct {
	// tcpPorts is filled in when matching a wildcarded source port for a TCP SYN.
	// Subsequent non-SYN TCP matches using the same FlowContext will match this stored port number.
	// Keyed by the known destination port so that we can track multiple connections at the same time
	tcpPorts portMap

	// udpPorts is filled in when matching a wildcarded source port for a UDP request.
	// Subsequent UDP matches using the same FlowContext will match this stored port number.
	// Keyed by the known destination port so that we can track multiple connections at the same time
	udpPorts portMap
}

func NewFlowContext() FlowContext {
	return FlowContext{
		tcpPorts: make(portMap, 1),
		udpPorts: make(portMap, 1),
	}
}

// FlowFilterFunc is a function to filter on a condition in a flow. It returns
// true if the condition is true.
type FlowFilterFunc func(flow *flowpb.Flow, fc *FlowContext) bool

type FlowFilterImplementation interface {
	Match(flow *flowpb.Flow, fc *FlowContext) bool
	String(fc *FlowContext) string
}

type FlowRequirement struct {
	Filter            FlowFilterImplementation
	Msg               string
	SkipOnAggregation bool
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

func (a *andFilter) Match(flow *flowpb.Flow, fc *FlowContext) bool {
	for _, f := range a.filters {
		if !f.Match(flow, fc) {
			return false
		}
	}
	return true
}

func (a *andFilter) String(fc *FlowContext) string {
	var s []string
	for _, f := range a.filters {
		s = append(s, f.String(fc))
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

func (o *orFilter) Match(flow *flowpb.Flow, fc *FlowContext) bool {
	for _, f := range o.filters {
		if f.Match(flow, fc) {
			return true
		}
	}
	return false
}

func (o *orFilter) String(fc *FlowContext) string {
	var s []string
	for _, f := range o.filters {
		s = append(s, f.String(fc))
	}
	return "or(" + strings.Join(s, ",") + ")"
}

// Or returns true if any FlowFilterImplementation return true
func Or(filters ...FlowFilterImplementation) FlowFilterImplementation {
	return &orFilter{filters: filters}
}

type dropFilter struct{}

func (d *dropFilter) Match(flow *flowpb.Flow, fc *FlowContext) bool {
	return flow.GetDropReasonDesc() != flowpb.DropReason_DROP_REASON_UNKNOWN
}

func (d *dropFilter) String(fc *FlowContext) string {
	return "drop"
}

// Drop matches on drops
func Drop() FlowFilterImplementation {
	return &dropFilter{}
}

type l7DropFilter struct{}

func (d *l7DropFilter) Match(flow *flowpb.Flow, fc *FlowContext) bool {
	l7 := flow.GetL7()
	if l7 == nil {
		return false
	}
	return flow.GetVerdict() == flowpb.Verdict_DROPPED
}

func (d *l7DropFilter) String(fc *FlowContext) string {
	return "l7 drop"
}

// L7Drop matches on drops reported by L7 proxied
func L7Drop() FlowFilterImplementation {
	return &l7DropFilter{}
}

type icmpFilter struct {
	typ uint32
}

func (i *icmpFilter) Match(flow *flowpb.Flow, fc *FlowContext) bool {
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

func (i *icmpFilter) String(fc *FlowContext) string {
	return fmt.Sprintf("icmp(%d)", i.typ)
}

// ICMP matches on ICMP messages of the specified type
func ICMP(typ uint32) FlowFilterImplementation {
	return &icmpFilter{typ: typ}
}

type icmpv6Filter struct {
	typ uint32
}

func (i *icmpv6Filter) Match(flow *flowpb.Flow, fc *FlowContext) bool {
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

func (i *icmpv6Filter) String(fc *FlowContext) string {
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

func (u *udpFilter) Match(flow *flowpb.Flow, fc *FlowContext) bool {
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

	if u.srcPort == 0 { // wildcarded source port
		fc.udpPorts[udp.DestinationPort] = udp.SourcePort
	}
	// Match previously seen (ephemeral) source port as the destination port?
	if u.dstPort == 0 && fc.udpPorts[udp.SourcePort] != udp.DestinationPort {
		return false
	}

	return true
}

func (u *udpFilter) String(fc *FlowContext) string {
	var s []string
	srcPort := u.srcPort
	if srcPort == 0 {
		srcPort = int(fc.udpPorts[uint32(u.dstPort)])
	}
	if srcPort != 0 {
		s = append(s, fmt.Sprintf("srcPort=%d", srcPort))
	}
	dstPort := u.dstPort
	if dstPort == 0 {
		dstPort = int(fc.udpPorts[uint32(u.srcPort)])
	}
	if dstPort != 0 {
		s = append(s, fmt.Sprintf("dstPort=%d", dstPort))
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

func (t *tcpFlagsFilter) Match(flow *flowpb.Flow, fc *FlowContext) bool {
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

func (t *tcpFlagsFilter) String(fc *FlowContext) string {
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

func (i *ipFilter) Match(flow *flowpb.Flow, fc *FlowContext) bool {
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

func (i *ipFilter) String(fc *FlowContext) string {
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
	srcPort uint32
	dstPort uint32
}

func (t *tcpFilter) Match(flow *flowpb.Flow, fc *FlowContext) bool {
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

	if t.srcPort == 0 {
		if tcp.Flags != nil && tcp.Flags.SYN && !tcp.Flags.ACK && !tcp.Flags.FIN && !tcp.Flags.RST {
			// save wildcarded source port
			fc.tcpPorts[tcp.DestinationPort] = tcp.SourcePort
		} else if tcp.SourcePort != fc.tcpPorts[tcp.DestinationPort] {
			return false
		}
	}

	// Match previously seen (ephemeral) source port as the destination port?
	if t.dstPort == 0 && tcp.DestinationPort != fc.tcpPorts[tcp.SourcePort] {
		return false
	}

	return true
}

func (t *tcpFilter) String(fc *FlowContext) string {
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
func TCP(srcPort, dstPort uint32) FlowFilterImplementation {
	return &tcpFilter{srcPort: srcPort, dstPort: dstPort}
}

type dnsFilter struct {
	query string
	rcode uint32
}

func (d *dnsFilter) Match(flow *flowpb.Flow, fc *FlowContext) bool {
	l7 := flow.GetL7()
	if l7 == nil {
		return false
	}

	dns := l7.GetDns()
	if dns == nil {
		return false
	}

	if d.query != "" && dns.Query != d.query {
		return false
	}

	if d.rcode != math.MaxUint32 && dns.Rcode != d.rcode {
		return false
	}

	return true
}

func (d *dnsFilter) String(fc *FlowContext) string {
	var s []string
	if d.query != "" {
		s = append(s, fmt.Sprintf("query=%s", d.query))
	}
	if d.rcode != math.MaxUint32 {
		s = append(s, fmt.Sprintf("rcode=%d", d.rcode))
	}
	return "dns(" + strings.Join(s, ",") + ")"
}

// DNS matches on proxied DNS packets containing a specific value, if any
func DNS(query string, rcode uint32) FlowFilterImplementation {
	return &dnsFilter{query: query, rcode: rcode}
}

type httpFilter struct {
	code     uint32
	method   string
	url      string
	protocol string
	headers  map[string]string
}

func (h *httpFilter) Match(flow *flowpb.Flow, fc *FlowContext) bool {
	l7 := flow.GetL7()
	if l7 == nil {
		return false
	}

	http := l7.GetHttp()
	if http == nil {
		return false
	}

	if h.code != math.MaxUint32 && http.Code != h.code {
		return false
	}

	if h.method != "" && http.Method != h.method {
		return false
	}

	if h.url != "" && http.Url != h.url {
		return false
	}

	if h.protocol != "" && http.Protocol != h.protocol {
		return false
	}

	for k, v := range h.headers {
		idx := -1
		for i, hdr := range http.Headers {
			if hdr != nil && hdr.Key == k && (v == "" || hdr.Value == v) {
				idx = i
			}
		}
		if idx < 0 {
			return false
		}
	}
	return true
}

func (h *httpFilter) String(fc *FlowContext) string {
	var s []string
	if h.code != math.MaxUint32 {
		s = append(s, fmt.Sprintf("code=%d", h.code))
	}
	if h.method != "" {
		s = append(s, fmt.Sprintf("method=%s", h.method))
	}
	if h.url != "" {
		s = append(s, fmt.Sprintf("url=%s", h.url))
	}
	if h.protocol != "" {
		s = append(s, fmt.Sprintf("protocol=%s", h.protocol))
	}
	if len(h.headers) > 0 {
		var hs []string
		for k, v := range h.headers {
			hs = append(hs, fmt.Sprintf("%s=%s", k, v))
		}
		s = append(s, "headers=("+strings.Join(hs, ",")+")")
	}
	return "http(" + strings.Join(s, ",") + ")"
}

// HTTP matches on proxied HTTP packets containing a specific value, if any
func HTTP(code uint32, method, url string) FlowFilterImplementation {
	return &httpFilter{code: code, method: method, url: url}
}
