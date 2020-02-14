// Copyright 2019 Authors of Hubble
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

package threefour

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	pb "github.com/cilium/hubble/api/v1/flow"
	"github.com/cilium/hubble/pkg/logger"
	"github.com/cilium/hubble/pkg/parser/errors"
	"github.com/cilium/hubble/pkg/parser/getters"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Parser is a parser for L3/L4 payloads
type Parser struct {
	endpointGetter getters.EndpointGetter
	identityGetter getters.IdentityGetter
	dnsGetter      getters.DNSGetter
	ipGetter       getters.IPGetter
	serviceGetter  getters.ServiceGetter

	// TODO: consider using a pool of these
	packet *packet
}

// re-usable packet to avoid reallocating gopacket datastructures
type packet struct {
	sync.Mutex
	decLayer *gopacket.DecodingLayerParser
	Layers   []gopacket.LayerType
	layers.Ethernet
	layers.IPv4
	layers.IPv6
	layers.ICMPv4
	layers.ICMPv6
	layers.TCP
	layers.UDP
}

// New returns a new L3/L4 parser
func New(
	endpointGetter getters.EndpointGetter,
	identityGetter getters.IdentityGetter,
	dnsGetter getters.DNSGetter,
	ipGetter getters.IPGetter,
	serviceGetter getters.ServiceGetter,
) (*Parser, error) {
	packet := &packet{}
	packet.decLayer = gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet, &packet.Ethernet,
		&packet.IPv4, &packet.IPv6,
		&packet.ICMPv4, &packet.ICMPv6, &packet.TCP, &packet.UDP)

	return &Parser{
		dnsGetter:      dnsGetter,
		endpointGetter: endpointGetter,
		identityGetter: identityGetter,
		ipGetter:       ipGetter,
		serviceGetter:  serviceGetter,
		packet:         packet,
	}, nil
}

// Decode decodes the data from 'payload' into 'decoded'
func (p *Parser) Decode(payload *pb.Payload, decoded *pb.Flow) error {
	if payload == nil || len(payload.Data) == 0 {
		return errors.ErrEmptyData
	}

	var packetOffset int
	var eventType uint8
	eventType = payload.Data[0]
	var dn *monitor.DropNotify
	var tn *monitor.TraceNotify
	var eventSubType uint8
	switch eventType {
	case monitorAPI.MessageTypeDrop:
		packetOffset = monitor.DropNotifyLen
		dn = &monitor.DropNotify{}
		if err := binary.Read(bytes.NewReader(payload.Data), byteorder.Native, dn); err != nil {
			return fmt.Errorf("failed to parse drop: %v", err)
		}
		eventSubType = dn.SubType
	case monitorAPI.MessageTypeTrace:
		tn = &monitor.TraceNotify{}
		if err := monitor.DecodeTraceNotify(payload.Data, tn); err != nil {
			return fmt.Errorf("failed to parse trace: %v", err)
		}
		eventSubType = tn.ObsPoint
		packetOffset = (int)(tn.DataOffset())
	default:
		return errors.NewErrInvalidType(eventType)
	}

	if len(payload.Data) < packetOffset {
		return fmt.Errorf("not enough bytes to decode %d", payload.Data)
	}

	p.packet.Lock()
	defer p.packet.Unlock()

	err := p.packet.decLayer.DecodeLayers(payload.Data[packetOffset:], &p.packet.Layers)
	if err != nil && !strings.HasPrefix(err.Error(), "No decoder for layer type") {
		return err
	}

	ether, ip, l4, srcIP, dstIP, srcPort, dstPort, summary := decodeLayers(p.packet)
	if tn != nil && !tn.OriginalIP().IsUnspecified() {
		srcIP = tn.OriginalIP()
		if ip != nil {
			ip.Source = srcIP.String()
		}
	}

	srcLabelID, dstLabelID := decodeSecurityIdentities(dn, tn)
	srcEndpoint := p.resolveEndpoint(srcIP, srcLabelID)
	dstEndpoint := p.resolveEndpoint(dstIP, dstLabelID)
	var sourceService, destinationService *pb.Service
	if p.serviceGetter != nil {
		if srcService, ok := p.serviceGetter.GetServiceByAddr(srcIP, srcPort); ok {
			sourceService = &srcService
		}
		if dstService, ok := p.serviceGetter.GetServiceByAddr(dstIP, dstPort); ok {
			destinationService = &dstService
		}
	}

	decoded.Time = payload.Time
	decoded.Verdict = decodeVerdict(eventType)
	decoded.DropReason = decodeDropReason(dn)
	decoded.Ethernet = ether
	decoded.IP = ip
	decoded.L4 = l4
	decoded.Source = srcEndpoint
	decoded.Destination = dstEndpoint
	decoded.Type = pb.FlowType_L3_L4
	decoded.NodeName = payload.HostName
	decoded.SourceNames = p.resolveNames(dstEndpoint.ID, srcIP)
	decoded.DestinationNames = p.resolveNames(srcEndpoint.ID, dstIP)
	decoded.L7 = nil
	decoded.Reply = decodeIsReply(tn)
	decoded.EventType = decodeCiliumEventType(eventType, eventSubType)
	decoded.SourceService = sourceService
	decoded.DestinationService = destinationService
	decoded.Summary = summary

	return nil
}

func (p *Parser) resolveNames(epID uint64, ip net.IP) (names []string) {
	if p.dnsGetter != nil {
		return p.dnsGetter.GetNamesOf(epID, ip)
	}

	return nil
}

func filterCidrLabels(labels []string) []string {
	// Cilium might return a bunch of cidr labels with different prefix length. Filter out all
	// but the longest prefix cidr label, which can be useful for troubleshooting. This also
	// relies on the fact that when a Cilium security identity has multiple CIDR labels, longer
	// prefix is always a subset of shorter prefix.
	cidrPrefix := "cidr:"
	var filteredLabels []string
	var max *net.IPNet
	var maxStr string
	log := logger.GetLogger()
	for _, label := range labels {
		if strings.HasPrefix(label, cidrPrefix) {
			currLabel := label[len(cidrPrefix):]
			_, curr, err := net.ParseCIDR(currLabel)
			if err != nil {
				log.WithField("label", label).Warn("got an invalid cidr label")
				continue
			}
			if max == nil {
				max = curr
				maxStr = label
			}
			currMask, _ := curr.Mask.Size()
			maxMask, _ := max.Mask.Size()
			if currMask > maxMask {
				max = curr
				maxStr = label
			}
		} else {
			filteredLabels = append(filteredLabels, label)
		}
	}
	if max != nil {
		filteredLabels = append(filteredLabels, maxStr)
	}
	return filteredLabels
}

func sortAndFilterLabels(labels []string, securityIdentity uint64) []string {
	if securityIdentity&uint64(identity.LocalIdentityFlag) != 0 {
		labels = filterCidrLabels(labels)
	}
	sort.Strings(labels)
	return labels
}

func (p *Parser) resolveEndpoint(ip net.IP, securityIdentity uint64) *pb.Endpoint {
	// for local endpoints, use the available endpoint information
	if p.endpointGetter != nil {
		if ep, ok := p.endpointGetter.GetEndpoint(ip); ok {
			return &pb.Endpoint{
				ID:        ep.ID,
				Identity:  securityIdentity,
				Namespace: ep.PodNamespace,
				Labels:    sortAndFilterLabels(ep.Labels, securityIdentity),
				PodName:   ep.PodName,
			}
		}
	}

	// for remote endpoints, assemble the information via ip and identity
	var namespace, podName string
	if p.ipGetter != nil {
		if ipIdentity, ok := p.ipGetter.GetIPIdentity(ip); ok {
			securityIdentity = uint64(ipIdentity.Identity)
			namespace, podName = ipIdentity.Namespace, ipIdentity.PodName
		}
	}
	var labels []string
	if p.identityGetter != nil {
		if id, err := p.identityGetter.GetIdentity(securityIdentity); err != nil {
			logger.GetLogger().
				WithError(err).WithField("identity", securityIdentity).
				Warn("failed to resolve identity")
		} else {
			labels = sortAndFilterLabels(id.Labels, securityIdentity)
		}
	}

	return &pb.Endpoint{
		Identity:  securityIdentity,
		Namespace: namespace,
		Labels:    labels,
		PodName:   podName,
	}
}

func decodeLayers(packet *packet) (
	ethernet *pb.Ethernet,
	ip *pb.IP,
	l4 *pb.Layer4,
	sourceIP, destinationIP net.IP,
	sourcePort, destinationPort uint16,
	summary string) {
	for _, typ := range packet.Layers {
		summary = typ.String()
		switch typ {
		case layers.LayerTypeEthernet:
			ethernet = decodeEthernet(&packet.Ethernet)
		case layers.LayerTypeIPv4:
			ip, sourceIP, destinationIP = decodeIPv4(&packet.IPv4)
		case layers.LayerTypeIPv6:
			ip, sourceIP, destinationIP = decodeIPv6(&packet.IPv6)
		case layers.LayerTypeTCP:
			l4, sourcePort, destinationPort = decodeTCP(&packet.TCP)
			summary = "TCP Flags: " + getTCPFlags(packet.TCP)
		case layers.LayerTypeUDP:
			l4, sourcePort, destinationPort = decodeUDP(&packet.UDP)
		case layers.LayerTypeICMPv4:
			l4 = decodeICMPv4(&packet.ICMPv4)
			summary = "ICMPv4 " + packet.ICMPv4.TypeCode.String()
		case layers.LayerTypeICMPv6:
			l4 = decodeICMPv6(&packet.ICMPv6)
			summary = "ICMPv6 " + packet.ICMPv6.TypeCode.String()
		}
	}

	return
}

func decodeVerdict(eventType uint8) pb.Verdict {
	switch eventType {
	case monitorAPI.MessageTypeDrop:
		return pb.Verdict_DROPPED
	case monitorAPI.MessageTypeTrace:
		return pb.Verdict_FORWARDED
	default:
		return pb.Verdict_VERDICT_UNKNOWN
	}
}

func decodeDropReason(dn *monitor.DropNotify) uint32 {
	if dn != nil {
		return uint32(dn.SubType)
	}
	return 0
}

func decodeEthernet(ethernet *layers.Ethernet) *pb.Ethernet {
	return &pb.Ethernet{
		Source:      ethernet.SrcMAC.String(),
		Destination: ethernet.DstMAC.String(),
	}
}

func decodeIPv4(ipv4 *layers.IPv4) (ip *pb.IP, src, dst net.IP) {
	return &pb.IP{
		Source:      ipv4.SrcIP.String(),
		Destination: ipv4.DstIP.String(),
		IpVersion:   pb.IPVersion_IPv4,
	}, ipv4.SrcIP, ipv4.DstIP
}

func decodeIPv6(ipv6 *layers.IPv6) (ip *pb.IP, src, dst net.IP) {
	return &pb.IP{
		Source:      ipv6.SrcIP.String(),
		Destination: ipv6.DstIP.String(),
		IpVersion:   pb.IPVersion_IPv6,
	}, ipv6.SrcIP, ipv6.DstIP
}

func decodeTCP(tcp *layers.TCP) (l4 *pb.Layer4, src, dst uint16) {
	return &pb.Layer4{
		Protocol: &pb.Layer4_TCP{
			TCP: &pb.TCP{
				SourcePort:      uint32(tcp.SrcPort),
				DestinationPort: uint32(tcp.DstPort),
				Flags: &pb.TCPFlags{
					FIN: tcp.FIN, SYN: tcp.SYN, RST: tcp.RST,
					PSH: tcp.PSH, ACK: tcp.ACK, URG: tcp.URG,
					ECE: tcp.ECE, CWR: tcp.CWR, NS: tcp.NS,
				},
			},
		},
	}, uint16(tcp.SrcPort), uint16(tcp.DstPort)
}

func decodeUDP(udp *layers.UDP) (l4 *pb.Layer4, src, dst uint16) {
	return &pb.Layer4{
		Protocol: &pb.Layer4_UDP{
			UDP: &pb.UDP{
				SourcePort:      uint32(udp.SrcPort),
				DestinationPort: uint32(udp.DstPort),
			},
		},
	}, uint16(udp.SrcPort), uint16(udp.DstPort)
}

func decodeICMPv4(icmp *layers.ICMPv4) *pb.Layer4 {
	return &pb.Layer4{
		Protocol: &pb.Layer4_ICMPv4{ICMPv4: &pb.ICMPv4{
			Type: uint32(icmp.TypeCode.Type()),
			Code: uint32(icmp.TypeCode.Code()),
		}},
	}
}

func decodeICMPv6(icmp *layers.ICMPv6) *pb.Layer4 {
	return &pb.Layer4{
		Protocol: &pb.Layer4_ICMPv6{ICMPv6: &pb.ICMPv6{
			Type: uint32(icmp.TypeCode.Type()),
			Code: uint32(icmp.TypeCode.Code()),
		}},
	}
}

func decodeIsReply(tn *monitor.TraceNotify) bool {
	return tn != nil && tn.Reason == monitor.TraceReasonCtReply
}

func decodeCiliumEventType(eventType, eventSubType uint8) *pb.CiliumEventType {
	return &pb.CiliumEventType{
		Type:    int32(eventType),
		SubType: int32(eventSubType),
	}
}

func decodeSecurityIdentities(dn *monitor.DropNotify, tn *monitor.TraceNotify) (
	sourceSecurityIdentiy, destinationSecurityIdentity uint64,
) {
	switch {
	case dn != nil:
		sourceSecurityIdentiy = uint64(dn.SrcLabel)
		destinationSecurityIdentity = uint64(dn.DstLabel)
	case tn != nil:
		sourceSecurityIdentiy = uint64(tn.SrcLabel)
		destinationSecurityIdentity = uint64(tn.DstLabel)
	}

	return
}

func getTCPFlags(tcp layers.TCP) string {
	const (
		syn         = "SYN"
		ack         = "ACK"
		rst         = "RST"
		fin         = "FIN"
		psh         = "PSH"
		urg         = "URG"
		ece         = "ECE"
		cwr         = "CWR"
		ns          = "NS"
		maxTCPFlags = 9
		comma       = ", "
	)

	info := make([]string, 0, maxTCPFlags)

	if tcp.SYN {
		info = append(info, syn)
	}

	if tcp.ACK {
		info = append(info, ack)
	}

	if tcp.RST {
		info = append(info, rst)
	}

	if tcp.FIN {
		info = append(info, fin)
	}

	if tcp.PSH {
		info = append(info, psh)
	}

	if tcp.URG {
		info = append(info, urg)
	}

	if tcp.ECE {
		info = append(info, ece)
	}

	if tcp.CWR {
		info = append(info, cwr)
	}

	if tcp.NS {
		info = append(info, ns)
	}

	return strings.Join(info, comma)
}
