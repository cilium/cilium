// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package threefour

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/api/v1/flow"
	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/hubble/parser/common"
	"github.com/cilium/cilium/pkg/hubble/parser/errors"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	ippkg "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

// Parser is a parser for L3/L4 payloads
type Parser struct {
	log            logrus.FieldLogger
	endpointGetter getters.EndpointGetter
	identityGetter getters.IdentityGetter
	dnsGetter      getters.DNSGetter
	ipGetter       getters.IPGetter
	serviceGetter  getters.ServiceGetter
	linkGetter     getters.LinkGetter

	epResolver *common.EndpointResolver

	// TODO: consider using a pool of these
	packet *packet
}

// re-usable packet to avoid reallocating gopacket datastructures
type packet struct {
	lock.Mutex
	decLayer *gopacket.DecodingLayerParser
	Layers   []gopacket.LayerType
	layers.Ethernet
	layers.IPv4
	layers.IPv6
	layers.ICMPv4
	layers.ICMPv6
	layers.TCP
	layers.UDP
	layers.SCTP
}

// New returns a new L3/L4 parser
func New(
	log logrus.FieldLogger,
	endpointGetter getters.EndpointGetter,
	identityGetter getters.IdentityGetter,
	dnsGetter getters.DNSGetter,
	ipGetter getters.IPGetter,
	serviceGetter getters.ServiceGetter,
	linkGetter getters.LinkGetter,
) (*Parser, error) {
	packet := &packet{}
	packet.decLayer = gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet, &packet.Ethernet,
		&packet.IPv4, &packet.IPv6,
		&packet.ICMPv4, &packet.ICMPv6,
		&packet.TCP, &packet.UDP, &packet.SCTP)
	// Let packet.decLayer.DecodeLayers return a nil error when it
	// encounters a layer it doesn't have a parser for, instead of returning
	// an UnsupportedLayerType error.
	packet.decLayer.IgnoreUnsupported = true

	return &Parser{
		log:            log,
		dnsGetter:      dnsGetter,
		endpointGetter: endpointGetter,
		identityGetter: identityGetter,
		ipGetter:       ipGetter,
		serviceGetter:  serviceGetter,
		linkGetter:     linkGetter,
		epResolver:     common.NewEndpointResolver(log, endpointGetter, identityGetter, ipGetter),
		packet:         packet,
	}, nil
}

// Decode decodes the data from 'data' into 'decoded'
func (p *Parser) Decode(data []byte, decoded *pb.Flow) error {
	if len(data) == 0 {
		return errors.ErrEmptyData
	}

	var packetOffset int
	var eventType uint8
	eventType = data[0]
	var dn *monitor.DropNotify
	var tn *monitor.TraceNotify
	var pvn *monitor.PolicyVerdictNotify
	var dbg *monitor.DebugCapture
	var eventSubType uint8
	var authType flow.AuthType
	switch eventType {
	case monitorAPI.MessageTypeDrop:
		packetOffset = monitor.DropNotifyLen
		dn = &monitor.DropNotify{}
		if err := binary.Read(bytes.NewReader(data), byteorder.Native, dn); err != nil {
			return fmt.Errorf("failed to parse drop: %v", err)
		}
		eventSubType = dn.SubType
	case monitorAPI.MessageTypeTrace:
		tn = &monitor.TraceNotify{}
		if err := monitor.DecodeTraceNotify(data, tn); err != nil {
			return fmt.Errorf("failed to parse trace: %v", err)
		}
		eventSubType = tn.ObsPoint

		if tn.ObsPoint != 0 {
			decoded.TraceObservationPoint = pb.TraceObservationPoint(tn.ObsPoint)
		} else {
			// specifically handle the zero value in the observation enum so the json
			// export and the API don't carry extra meaning with the zero value
			decoded.TraceObservationPoint = pb.TraceObservationPoint_TO_ENDPOINT
		}

		packetOffset = (int)(tn.DataOffset())
	case monitorAPI.MessageTypePolicyVerdict:
		pvn = &monitor.PolicyVerdictNotify{}
		if err := binary.Read(bytes.NewReader(data), byteorder.Native, pvn); err != nil {
			return fmt.Errorf("failed to parse policy verdict: %v", err)
		}
		eventSubType = pvn.SubType
		packetOffset = monitor.PolicyVerdictNotifyLen
		authType = flow.AuthType(pvn.GetAuthType())
	case monitorAPI.MessageTypeCapture:
		dbg = &monitor.DebugCapture{}
		if err := binary.Read(bytes.NewReader(data), byteorder.Native, dbg); err != nil {
			return fmt.Errorf("failed to parse debug capture: %w", err)
		}
		eventSubType = dbg.SubType
		packetOffset = monitor.DebugCaptureLen
	default:
		return errors.NewErrInvalidType(eventType)
	}

	if len(data) < packetOffset {
		return fmt.Errorf("not enough bytes to decode %d", data)
	}

	p.packet.Lock()
	defer p.packet.Unlock()

	// Since v1.1.18, DecodeLayers returns a non-nil error for an empty packet, see
	// https://github.com/google/gopacket/issues/846
	// TODO: reconsider this check if the issue is fixed upstream
	if len(data[packetOffset:]) > 0 {
		err := p.packet.decLayer.DecodeLayers(data[packetOffset:], &p.packet.Layers)
		if err != nil {
			return err
		}
	} else {
		// Truncate layers to avoid accidental re-use.
		p.packet.Layers = p.packet.Layers[:0]
	}

	ether, ip, l4, srcIP, dstIP, srcPort, dstPort, summary := decodeLayers(p.packet)
	if tn != nil {
		if !tn.OriginalIP().IsUnspecified() {
			// Ignore invalid IP - getters will handle invalid value.
			srcIP, _ = ippkg.AddrFromIP(tn.OriginalIP())
			if ip != nil {
				ip.Source = srcIP.String()
			}
		}

		if ip != nil {
			ip.Encrypted = (tn.Reason & monitor.TraceReasonEncryptMask) != 0
		}
	}

	srcLabelID, dstLabelID := decodeSecurityIdentities(dn, tn, pvn)
	srcEndpoint := p.epResolver.ResolveEndpoint(srcIP, srcLabelID)
	dstEndpoint := p.epResolver.ResolveEndpoint(dstIP, dstLabelID)
	var sourceService, destinationService *pb.Service
	if p.serviceGetter != nil {
		sourceService = p.serviceGetter.GetServiceByAddr(srcIP, srcPort)
		destinationService = p.serviceGetter.GetServiceByAddr(dstIP, dstPort)
	}

	decoded.Verdict = decodeVerdict(dn, tn, pvn)
	decoded.AuthType = authType
	decoded.DropReason = decodeDropReason(dn, pvn)
	decoded.DropReasonDesc = pb.DropReason(decoded.DropReason)
	decoded.Ethernet = ether
	decoded.IP = ip
	decoded.L4 = l4
	decoded.Source = srcEndpoint
	decoded.Destination = dstEndpoint
	decoded.Type = pb.FlowType_L3_L4
	decoded.SourceNames = p.resolveNames(dstEndpoint.ID, srcIP)
	decoded.DestinationNames = p.resolveNames(srcEndpoint.ID, dstIP)
	decoded.L7 = nil
	decoded.IsReply = decodeIsReply(tn, pvn)
	decoded.Reply = decoded.GetIsReply().GetValue() // false if GetIsReply() is nil
	decoded.TrafficDirection = decodeTrafficDirection(srcEndpoint.ID, dn, tn, pvn)
	decoded.EventType = decodeCiliumEventType(eventType, eventSubType)
	decoded.SourceService = sourceService
	decoded.DestinationService = destinationService
	decoded.PolicyMatchType = decodePolicyMatchType(pvn)
	decoded.DebugCapturePoint = decodeDebugCapturePoint(dbg)
	decoded.Interface = p.decodeNetworkInterface(tn, dbg)
	decoded.ProxyPort = decodeProxyPort(dbg, tn)
	decoded.Summary = summary

	return nil
}

func (p *Parser) resolveNames(epID uint32, ip netip.Addr) (names []string) {
	if p.dnsGetter != nil {
		return p.dnsGetter.GetNamesOf(epID, ip)
	}

	return nil
}

func decodeLayers(packet *packet) (
	ethernet *pb.Ethernet,
	ip *pb.IP,
	l4 *pb.Layer4,
	sourceIP, destinationIP netip.Addr,
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
		case layers.LayerTypeSCTP:
			l4, sourcePort, destinationPort = decodeSCTP(&packet.SCTP)
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

func decodeVerdict(dn *monitor.DropNotify, tn *monitor.TraceNotify, pvn *monitor.PolicyVerdictNotify) pb.Verdict {
	switch {
	case dn != nil:
		return pb.Verdict_DROPPED
	case tn != nil:
		return pb.Verdict_FORWARDED
	case pvn != nil:
		if pvn.Verdict < 0 {
			return pb.Verdict_DROPPED
		}
		if pvn.Verdict > 0 {
			return pb.Verdict_REDIRECTED
		}
		if pvn.IsTrafficAudited() {
			return pb.Verdict_AUDIT
		}
		return pb.Verdict_FORWARDED
	}
	return pb.Verdict_VERDICT_UNKNOWN
}

func decodeDropReason(dn *monitor.DropNotify, pvn *monitor.PolicyVerdictNotify) uint32 {
	switch {
	case dn != nil:
		return uint32(dn.SubType)
	case pvn != nil && pvn.Verdict < 0:
		// if the flow was dropped, verdict equals the negative of the drop reason
		return uint32(-pvn.Verdict)
	}
	return 0
}

func decodePolicyMatchType(pvn *monitor.PolicyVerdictNotify) uint32 {
	if pvn != nil {
		return uint32((pvn.Flags & monitor.PolicyVerdictNotifyFlagMatchType) >>
			monitor.PolicyVerdictNotifyFlagMatchTypeBitOffset)
	}
	return 0
}

func decodeEthernet(ethernet *layers.Ethernet) *pb.Ethernet {
	return &pb.Ethernet{
		Source:      ethernet.SrcMAC.String(),
		Destination: ethernet.DstMAC.String(),
	}
}

func decodeIPv4(ipv4 *layers.IPv4) (ip *pb.IP, src, dst netip.Addr) {
	// Ignore invalid IPs - getters will handle invalid values.
	// IPs can be empty for Ethernet-only packets.
	src, _ = ippkg.AddrFromIP(ipv4.SrcIP)
	dst, _ = ippkg.AddrFromIP(ipv4.DstIP)
	return &pb.IP{
		Source:      ipv4.SrcIP.String(),
		Destination: ipv4.DstIP.String(),
		IpVersion:   pb.IPVersion_IPv4,
	}, src, dst
}

func decodeIPv6(ipv6 *layers.IPv6) (ip *pb.IP, src, dst netip.Addr) {
	// Ignore invalid IPs - getters will handle invalid values.
	// IPs can be empty for Ethernet-only packets.
	src, _ = ippkg.AddrFromIP(ipv6.SrcIP)
	dst, _ = ippkg.AddrFromIP(ipv6.DstIP)
	return &pb.IP{
		Source:      ipv6.SrcIP.String(),
		Destination: ipv6.DstIP.String(),
		IpVersion:   pb.IPVersion_IPv6,
	}, src, dst
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

func decodeSCTP(sctp *layers.SCTP) (l4 *pb.Layer4, src, dst uint16) {
	return &pb.Layer4{
		Protocol: &pb.Layer4_SCTP{
			SCTP: &pb.SCTP{
				SourcePort:      uint32(sctp.SrcPort),
				DestinationPort: uint32(sctp.DstPort),
			},
		},
	}, uint16(sctp.SrcPort), uint16(sctp.DstPort)
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

func isReply(reason uint8) bool {
	return reason & ^monitor.TraceReasonEncryptMask == monitor.TraceReasonCtReply
}

func decodeIsReply(tn *monitor.TraceNotify, pvn *monitor.PolicyVerdictNotify) *wrapperspb.BoolValue {
	switch {
	case tn != nil && monitor.TraceReasonIsKnown(tn.Reason):
		// Reason was specified by the datapath, just reuse it.
		return &wrapperspb.BoolValue{
			Value: isReply(tn.Reason),
		}
	case pvn != nil && pvn.Verdict >= 0:
		// Forwarded PolicyVerdictEvents are emitted for the first packet of
		// connection, therefore we statically assume that they are not reply
		// packets
		return &wrapperspb.BoolValue{Value: false}
	default:
		// For other events, such as drops, we simply do not know if they were
		// replies or not.
		return nil
	}
}

func decodeCiliumEventType(eventType, eventSubType uint8) *pb.CiliumEventType {
	return &pb.CiliumEventType{
		Type:    int32(eventType),
		SubType: int32(eventSubType),
	}
}

func decodeSecurityIdentities(dn *monitor.DropNotify, tn *monitor.TraceNotify, pvn *monitor.PolicyVerdictNotify) (
	sourceSecurityIdentiy, destinationSecurityIdentity uint32,
) {
	switch {
	case dn != nil:
		sourceSecurityIdentiy = uint32(dn.SrcLabel)
		destinationSecurityIdentity = uint32(dn.DstLabel)
	case tn != nil:
		sourceSecurityIdentiy = uint32(tn.SrcLabel)
		destinationSecurityIdentity = uint32(tn.DstLabel)
	case pvn != nil:
		if pvn.IsTrafficIngress() {
			sourceSecurityIdentiy = uint32(pvn.RemoteLabel)
		} else {
			destinationSecurityIdentity = uint32(pvn.RemoteLabel)
		}
	}

	return
}

func decodeTrafficDirection(srcEP uint32, dn *monitor.DropNotify, tn *monitor.TraceNotify, pvn *monitor.PolicyVerdictNotify) pb.TrafficDirection {
	if dn != nil && dn.Source != 0 {
		// If the local endpoint at which the drop occurred is the same as the
		// source of the dropped packet, we assume it was an egress flow. This
		// implies that we also assume that dropped packets are not dropped
		// reply packets of an ongoing connection.
		if dn.Source == uint16(srcEP) {
			return pb.TrafficDirection_EGRESS
		}
		return pb.TrafficDirection_INGRESS
	}
	if tn != nil && tn.Source != 0 {
		// For trace events, we assume that packets may be reply packets of an
		// ongoing connection. Therefore, we want to access the connection
		// tracking result from the `Reason` field to invert the direction for
		// reply packets. The datapath currently populates the `Reason` field
		// with CT information for some observation points.
		if monitor.TraceReasonIsKnown(tn.Reason) {
			// true if the traffic source is the local endpoint, i.e. egress
			isSourceEP := tn.Source == uint16(srcEP)
			// true if the packet is a reply, i.e. reverse direction
			isReply := tn.Reason & ^monitor.TraceReasonEncryptMask == monitor.TraceReasonCtReply

			// isSourceEP != isReply ==
			//  (isSourceEP && !isReply) || (!isSourceEP && isReply)
			if isSourceEP != isReply {
				return pb.TrafficDirection_EGRESS
			}
			return pb.TrafficDirection_INGRESS
		}
	}
	if pvn != nil {
		if pvn.IsTrafficIngress() {
			return pb.TrafficDirection_INGRESS
		}
		return pb.TrafficDirection_EGRESS
	}
	return pb.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN
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

func decodeDebugCapturePoint(dbg *monitor.DebugCapture) pb.DebugCapturePoint {
	if dbg == nil {
		return pb.DebugCapturePoint_DBG_CAPTURE_POINT_UNKNOWN
	}
	return pb.DebugCapturePoint(dbg.SubType)
}

func (p *Parser) decodeNetworkInterface(tn *monitor.TraceNotify, dbg *monitor.DebugCapture) *pb.NetworkInterface {
	ifIndex := uint32(0)
	if tn != nil {
		ifIndex = tn.Ifindex
	} else if dbg != nil {
		switch dbg.SubType {
		case monitor.DbgCaptureDelivery,
			monitor.DbgCaptureFromLb,
			monitor.DbgCaptureAfterV46,
			monitor.DbgCaptureAfterV64,
			monitor.DbgCaptureSnatPre,
			monitor.DbgCaptureSnatPost:
			ifIndex = dbg.Arg1
		}
	}

	if ifIndex == 0 {
		return nil
	}

	var name string
	if p.linkGetter != nil {
		// if the interface is not found, `name` will be an empty string and thus
		// omitted in the protobuf message
		name, _ = p.linkGetter.GetIfNameCached(int(ifIndex))
	}
	return &pb.NetworkInterface{
		Index: ifIndex,
		Name:  name,
	}
}

func decodeProxyPort(dbg *monitor.DebugCapture, tn *monitor.TraceNotify) uint32 {
	if tn != nil && tn.ObsPoint == monitorAPI.TraceToProxy {
		return uint32(tn.DstID)
	} else if dbg != nil {
		switch dbg.SubType {
		case monitor.DbgCaptureProxyPre,
			monitor.DbgCaptureProxyPost:
			return byteorder.NetworkToHost32(dbg.Arg1)
		}
	}

	return 0
}
