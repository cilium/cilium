// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/gopacket/gopacket"
)

const (
	// IPv6HopByHopOptionJumbogram code as defined in RFC 2675
	IPv6HopByHopOptionJumbogram = 0xC2
)

const (
	ipv6MaxPayloadLength = 65535
	// ipv6MaxExtensionLength is the longest extension header the 8-bit
	// Hdr Ext Len field can describe: (255 + 1) * 8 bytes.
	ipv6MaxExtensionLength = 2048
)

// IPv6 is the layer for the IPv6 header.
type IPv6 struct {
	// http://www.networksorcery.com/enp/protocol/ipv6.htm
	BaseLayer
	Version      uint8
	TrafficClass uint8
	FlowLabel    uint32
	Length       uint16
	NextHeader   IPProtocol
	HopLimit     uint8
	SrcIP        net.IP
	DstIP        net.IP
	HopByHop     *IPv6HopByHop
	// hbh will be pointed to by HopByHop if that layer exists.
	hbh IPv6HopByHop
}

// LayerType returns LayerTypeIPv6
func (ipv6 *IPv6) LayerType() gopacket.LayerType { return LayerTypeIPv6 }

// NetworkFlow returns this new Flow (EndpointIPv6, SrcIP, DstIP)
func (ipv6 *IPv6) NetworkFlow() gopacket.Flow {
	return gopacket.NewFlow(EndpointIPv6, ipv6.SrcIP, ipv6.DstIP)
}

// Search for Jumbo Payload TLV in IPv6HopByHop and return (length, true) if found
func getIPv6HopByHopJumboLength(hopopts *IPv6HopByHop) (uint32, bool, error) {
	var tlv *IPv6HopByHopOption

	for _, t := range hopopts.Options {
		if t.OptionType == IPv6HopByHopOptionJumbogram {
			tlv = t
			break
		}
	}
	if tlv == nil {
		// Not found
		return 0, false, nil
	}
	if len(tlv.OptionData) != 4 {
		return 0, false, errors.New("Jumbo length TLV data must have length 4")
	}
	l := binary.BigEndian.Uint32(tlv.OptionData)
	if l <= ipv6MaxPayloadLength {
		return 0, false, fmt.Errorf("Jumbo length cannot be less than %d", ipv6MaxPayloadLength+1)
	}
	// Found
	return l, true, nil
}

// Adds zero-valued Jumbo TLV to IPv6 header if it does not exist
// (if necessary add hop-by-hop header)
func addIPv6JumboOption(ip6 *IPv6) {
	var tlv *IPv6HopByHopOption

	if ip6.HopByHop == nil {
		// Add IPv6 HopByHop
		ip6.HopByHop = &IPv6HopByHop{}
		ip6.HopByHop.NextHeader = ip6.NextHeader
		ip6.HopByHop.HeaderLength = 0
		ip6.NextHeader = IPProtocolIPv6HopByHop
	}
	for _, t := range ip6.HopByHop.Options {
		if t.OptionType == IPv6HopByHopOptionJumbogram {
			tlv = t
			break
		}
	}
	if tlv == nil {
		// Add Jumbo TLV
		tlv = &IPv6HopByHopOption{}
		ip6.HopByHop.Options = append(ip6.HopByHop.Options, tlv)
	}
	tlv.SetJumboLength(0)
}

// Set jumbo length in serialized IPv6 payload (starting with HopByHop header)
func setIPv6PayloadJumboLength(hbh []byte) error {
	pLen := len(hbh)
	if pLen < 8 {
		//HopByHop is minimum 8 bytes
		return fmt.Errorf("Invalid IPv6 payload (length %d)", pLen)
	}
	hbhLen := int((hbh[1] + 1) * 8)
	if hbhLen > pLen {
		return fmt.Errorf("Invalid hop-by-hop length (length: %d, payload: %d", hbhLen, pLen)
	}
	offset := 2 //start with options
	for offset < hbhLen {
		opt := hbh[offset]
		if opt == 0 {
			//Pad1
			offset++
			continue
		}
		optLen := int(hbh[offset+1])
		if opt == IPv6HopByHopOptionJumbogram {
			if optLen == 4 {
				binary.BigEndian.PutUint32(hbh[offset+2:], uint32(pLen))
				return nil
			}
			return fmt.Errorf("Jumbo TLV too short (%d bytes)", optLen)
		}
		offset += 2 + optLen
	}
	return errors.New("Jumbo TLV not found")
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (ipv6 *IPv6) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	var jumbo bool
	var err error

	payload := b.Bytes()
	pLen := len(payload)
	if pLen > ipv6MaxPayloadLength {
		jumbo = true
		if opts.FixLengths {
			// We need to set the length later because the hop-by-hop header may
			// not exist or else need padding, so pLen may yet change
			addIPv6JumboOption(ipv6)
		} else if ipv6.HopByHop == nil {
			return fmt.Errorf("Cannot fit payload length of %d into IPv6 packet", pLen)
		} else {
			_, ok, err := getIPv6HopByHopJumboLength(ipv6.HopByHop)
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("Missing jumbo length hop-by-hop option")
			}
		}
	}

	hbhAlreadySerialized := false
	if ipv6.HopByHop != nil {
		// The hop-by-hop header directly follows the IPv6 header, so only
		// the layer serialized last can be the one that belongs to this
		// header; an inner packet's header further down must not count.
		serialized := b.Layers()
		hbhAlreadySerialized = len(serialized) > 0 && serialized[len(serialized)-1] == LayerTypeIPv6HopByHop
	}
	if ipv6.HopByHop != nil && !hbhAlreadySerialized {
		if ipv6.NextHeader != IPProtocolIPv6HopByHop {
			// Just fix it instead of throwing an error
			ipv6.NextHeader = IPProtocolIPv6HopByHop
		}
		err = ipv6.HopByHop.SerializeTo(b, opts)
		if err != nil {
			return err
		}
		payload = b.Bytes()
		pLen = len(payload)
		if opts.FixLengths && jumbo {
			err := setIPv6PayloadJumboLength(payload)
			if err != nil {
				return err
			}
		}
	}

	if !jumbo && pLen > ipv6MaxPayloadLength {
		return errors.New("Cannot fit payload into IPv6 header")
	}
	bytes, err := b.PrependBytes(40)
	if err != nil {
		return err
	}
	bytes[0] = (ipv6.Version << 4) | (ipv6.TrafficClass >> 4)
	bytes[1] = (ipv6.TrafficClass << 4) | uint8(ipv6.FlowLabel>>16)
	binary.BigEndian.PutUint16(bytes[2:], uint16(ipv6.FlowLabel))
	if opts.FixLengths {
		if jumbo {
			ipv6.Length = 0
		} else {
			ipv6.Length = uint16(pLen)
		}
	}
	binary.BigEndian.PutUint16(bytes[4:], ipv6.Length)
	bytes[6] = byte(ipv6.NextHeader)
	bytes[7] = byte(ipv6.HopLimit)
	if err := ipv6.AddressTo16(); err != nil {
		return err
	}
	copy(bytes[8:], ipv6.SrcIP)
	copy(bytes[24:], ipv6.DstIP)
	return nil
}

// DecodeFromBytes implementation according to gopacket.DecodingLayer
func (ipv6 *IPv6) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 40 {
		df.SetTruncated()
		return fmt.Errorf("Invalid ip6 header. Length %d less than 40", len(data))
	}
	ipv6.Version = uint8(data[0]) >> 4
	ipv6.TrafficClass = uint8((binary.BigEndian.Uint16(data[0:2]) >> 4) & 0x00FF)
	ipv6.FlowLabel = binary.BigEndian.Uint32(data[0:4]) & 0x000FFFFF
	ipv6.Length = binary.BigEndian.Uint16(data[4:6])
	ipv6.NextHeader = IPProtocol(data[6])
	ipv6.HopLimit = data[7]
	ipv6.SrcIP = data[8:24]
	ipv6.DstIP = data[24:40]
	ipv6.HopByHop = nil
	ipv6.BaseLayer = BaseLayer{data[:40], data[40:]}

	// The payload length covers the extension headers as well (RFC 8200
	// section 3), so bound the payload by it before decoding any of them.
	// Otherwise the HopByHop header and the layer after it would be decoded
	// from bytes past the end of the IPv6 packet (e.g. a frame trailer).
	// A length of 0 means jumbogram and is handled with HopByHop below.
	if ipv6.Length != 0 {
		pEnd := int(ipv6.Length)
		if pEnd > len(ipv6.Payload) {
			df.SetTruncated()
			pEnd = len(ipv6.Payload)
		}
		ipv6.Payload = ipv6.Payload[:pEnd]
	}

	// We treat a HopByHop IPv6 option as part of the IPv6 packet, since its
	// options are crucial for understanding what's actually happening per packet.
	if ipv6.NextHeader == IPProtocolIPv6HopByHop {
		err := ipv6.hbh.DecodeFromBytes(ipv6.Payload, df)
		if err != nil {
			return err
		}
		ipv6.HopByHop = &ipv6.hbh
		pEnd, jumbo, err := getIPv6HopByHopJumboLength(ipv6.HopByHop)
		if err != nil {
			return err
		}
		if jumbo && ipv6.Length == 0 {
			pEnd := int(pEnd)
			if pEnd > len(ipv6.Payload) {
				df.SetTruncated()
				pEnd = len(ipv6.Payload)
			}
			// The jumbo length counts the HopByHop header, which belongs to
			// this layer: strip it as the non-jumbo branch does, so that
			// LayerPayload starts at the header NextLayerType names. The
			// check also catches a length that went negative in a 32-bit int.
			if pEnd < ipv6.hbh.ActualLength {
				return errors.New("IPv6 jumbo length shorter than the HopByHop header")
			}
			ipv6.Payload = ipv6.Payload[ipv6.hbh.ActualLength:pEnd]
			return nil
		} else if jumbo && ipv6.Length != 0 {
			return errors.New("IPv6 has jumbo length and IPv6 length is not 0")
		} else if !jumbo && ipv6.Length == 0 {
			return errors.New("IPv6 length 0, but HopByHop header does not have jumbogram option")
		} else {
			ipv6.Payload = ipv6.Payload[ipv6.hbh.ActualLength:]
		}
	}

	if ipv6.Length == 0 {
		return fmt.Errorf("IPv6 length 0, but next header is %v, not HopByHop", ipv6.NextHeader)
	}

	return nil
}

// CanDecode implementation according to gopacket.DecodingLayer
func (ipv6 *IPv6) CanDecode() gopacket.LayerClass {
	return LayerTypeIPv6
}

// NextLayerType implementation according to gopacket.DecodingLayer
func (ipv6 *IPv6) NextLayerType() gopacket.LayerType {
	if ipv6.HopByHop != nil {
		return ipv6.HopByHop.NextHeader.LayerType()
	}
	return ipv6.NextHeader.LayerType()
}

func decodeIPv6(data []byte, p gopacket.PacketBuilder) error {
	ip6 := &IPv6{}
	err := ip6.DecodeFromBytes(data, p)
	p.AddLayer(ip6)
	p.SetNetworkLayer(ip6)
	if ip6.HopByHop != nil {
		p.AddLayer(ip6.HopByHop)
	}
	if err != nil {
		return err
	}
	return p.NextDecoder(ip6.NextLayerType())
}

type ipv6HeaderTLVOption struct {
	OptionType, OptionLength uint8
	ActualLength             int
	OptionData               []byte
	OptionAlignment          [2]uint8 // Xn+Y = [2]uint8{X, Y}
}

func (h *ipv6HeaderTLVOption) serializeTo(data []byte, fixLengths bool, dryrun bool) int {
	// Pad1 is a single zero byte with no length and no data (RFC 8200 4.2)
	if h.OptionType == 0 {
		if !dryrun {
			data[0] = 0
		}
		return 1
	}
	if fixLengths {
		h.OptionLength = uint8(len(h.OptionData))
	}
	length := int(h.OptionLength) + 2
	if !dryrun {
		data[0] = h.OptionType
		data[1] = h.OptionLength
		copy(data[2:], h.OptionData)
	}
	return length
}

// decodeIPv6HeaderTLVOption decodes one option from data, which must hold
// only the remaining bytes of the extension header the option belongs to, so
// that an option cannot extend past the header into the next one.
func decodeIPv6HeaderTLVOption(data []byte, df gopacket.DecodeFeedback) (h *ipv6HeaderTLVOption, _ error) {
	if len(data) < 1 {
		return nil, errors.New("IPv6 header option too small")
	}
	h = &ipv6HeaderTLVOption{}
	// a Pad1 may be the last byte of the header
	if data[0] == 0 {
		// Pad1 is a single byte and may be the last byte of the header.
		h.ActualLength = 1
		return
	}
	if len(data) < 2 {
		return nil, errors.New("IPv6 header option too small")
	}
	h.OptionType = data[0]
	h.OptionLength = data[1]
	h.ActualLength = int(h.OptionLength) + 2
	if len(data) < h.ActualLength {
		return nil, errors.New("IPv6 header TLV option exceeds extension header")
	}
	h.OptionData = data[2:h.ActualLength]
	return
}

func serializeTLVOptionPadding(data []byte, padLength int) {
	if padLength <= 0 {
		return
	}
	if padLength == 1 {
		data[0] = 0x0
		return
	}
	tlvLength := uint8(padLength) - 2
	data[0] = 0x1
	data[1] = tlvLength
	if tlvLength != 0 {
		for k := range data[2:] {
			data[k+2] = 0x0
		}
	}
	return
}

// If buf is 'nil' do a serialize dry run
func serializeIPv6HeaderTLVOptions(buf []byte, options []*ipv6HeaderTLVOption, fixLengths bool) int {
	var l int

	dryrun := buf == nil
	length := 2
	for _, opt := range options {
		if fixLengths {
			x := int(opt.OptionAlignment[0])
			y := int(opt.OptionAlignment[1])
			if x != 0 {
				n := length / x
				offset := x*n + y
				if offset < length {
					offset += x
				}
				if length != offset {
					pad := offset - length
					if !dryrun {
						serializeTLVOptionPadding(buf[length-2:], pad)
					}
					length += pad
				}
			}
		}
		if dryrun {
			l = opt.serializeTo(nil, fixLengths, true)
		} else {
			l = opt.serializeTo(buf[length-2:], fixLengths, false)
		}
		length += l
	}
	if fixLengths {
		pad := length % 8
		if pad != 0 {
			if !dryrun {
				serializeTLVOptionPadding(buf[length-2:], pad)
			}
			length += pad
		}
	}
	return length - 2
}

type ipv6ExtensionBase struct {
	BaseLayer
	NextHeader   IPProtocol
	HeaderLength uint8
	ActualLength int
}

func decodeIPv6ExtensionBase(data []byte, df gopacket.DecodeFeedback) (i ipv6ExtensionBase, returnedErr error) {
	if len(data) < 2 {
		df.SetTruncated()
		return ipv6ExtensionBase{}, fmt.Errorf("Invalid ip6-extension header. Length %d less than 2", len(data))
	}
	i.NextHeader = IPProtocol(data[0])
	i.HeaderLength = data[1]
	i.ActualLength = int(i.HeaderLength)*8 + 8
	if len(data) < i.ActualLength {
		return ipv6ExtensionBase{}, fmt.Errorf("Invalid ip6-extension header. Length %d less than specified length %d", len(data), i.ActualLength)
	}
	i.Contents = data[:i.ActualLength]
	i.Payload = data[i.ActualLength:]
	return
}

// IPv6ExtensionSkipper is a DecodingLayer which decodes and ignores v6
// extensions.  You can use it with a DecodingLayerParser to handle IPv6 stacks
// which may or may not have extensions.
type IPv6ExtensionSkipper struct {
	NextHeader IPProtocol
	BaseLayer
}

// DecodeFromBytes implementation according to gopacket.DecodingLayer
func (i *IPv6ExtensionSkipper) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	extension, err := decodeIPv6ExtensionBase(data, df)
	if err != nil {
		return err
	}
	i.BaseLayer = BaseLayer{data[:extension.ActualLength], data[extension.ActualLength:]}
	i.NextHeader = extension.NextHeader
	return nil
}

// CanDecode implementation according to gopacket.DecodingLayer
func (i *IPv6ExtensionSkipper) CanDecode() gopacket.LayerClass {
	return LayerClassIPv6Extension
}

// NextLayerType implementation according to gopacket.DecodingLayer
func (i *IPv6ExtensionSkipper) NextLayerType() gopacket.LayerType {
	return i.NextHeader.LayerType()
}

// IPv6HopByHopOption is a TLV option present in an IPv6 hop-by-hop extension.
type IPv6HopByHopOption ipv6HeaderTLVOption

// IPv6HopByHop is the IPv6 hop-by-hop extension.
type IPv6HopByHop struct {
	ipv6ExtensionBase
	Options []*IPv6HopByHopOption
}

// LayerType returns LayerTypeIPv6HopByHop.
func (i *IPv6HopByHop) LayerType() gopacket.LayerType { return LayerTypeIPv6HopByHop }

// SerializeTo implementation according to gopacket.SerializableLayer
func (i *IPv6HopByHop) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	var bytes []byte
	var err error

	o := make([]*ipv6HeaderTLVOption, 0, len(i.Options))
	for _, v := range i.Options {
		o = append(o, (*ipv6HeaderTLVOption)(v))
	}

	l := serializeIPv6HeaderTLVOptions(nil, o, opts.FixLengths)
	bytes, err = b.PrependBytes(l)
	if err != nil {
		return err
	}
	serializeIPv6HeaderTLVOptions(bytes, o, opts.FixLengths)

	length := len(bytes) + 2
	if length%8 != 0 {
		return errors.New("IPv6HopByHop actual length must be multiple of 8")
	}
	if length > ipv6MaxExtensionLength {
		return fmt.Errorf("IPv6HopByHop actual length %d exceeds maximum of %d", length, ipv6MaxExtensionLength)
	}
	bytes, err = b.PrependBytes(2)
	if err != nil {
		return err
	}
	bytes[0] = uint8(i.NextHeader)
	if opts.FixLengths {
		i.HeaderLength = uint8((length / 8) - 1)
	}
	bytes[1] = uint8(i.HeaderLength)
	return nil
}

// DecodeFromBytes implementation according to gopacket.DecodingLayer
func (i *IPv6HopByHop) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	var err error
	i.ipv6ExtensionBase, err = decodeIPv6ExtensionBase(data, df)
	if err != nil {
		return err
	}
	i.Options = i.Options[:0]
	offset := 2
	for offset < i.ActualLength {
		opt, err := decodeIPv6HeaderTLVOption(data[offset:i.ActualLength], df)
		if err != nil {
			return err
		}
		i.Options = append(i.Options, (*IPv6HopByHopOption)(opt))
		offset += opt.ActualLength
	}
	return nil
}

func decodeIPv6HopByHop(data []byte, p gopacket.PacketBuilder) error {
	i := &IPv6HopByHop{}
	err := i.DecodeFromBytes(data, p)
	p.AddLayer(i)
	if err != nil {
		return err
	}
	return p.NextDecoder(i.NextHeader)
}

// SetJumboLength adds the IPv6HopByHopOptionJumbogram with the given length
func (o *IPv6HopByHopOption) SetJumboLength(len uint32) {
	o.OptionType = IPv6HopByHopOptionJumbogram
	o.OptionLength = 4
	o.ActualLength = 6
	if o.OptionData == nil {
		o.OptionData = make([]byte, 4)
	}
	binary.BigEndian.PutUint32(o.OptionData, len)
	o.OptionAlignment = [2]uint8{4, 2}
}

// IPv6Routing is the IPv6 routing extension.
type IPv6Routing struct {
	ipv6ExtensionBase
	RoutingType  uint8
	SegmentsLeft uint8
	// This segment is supposed to be zero according to RFC2460, the second set of
	// 4 bytes in the extension.
	Reserved []byte
	// SourceRoutingIPs is the set of IPv6 addresses requested for source routing,
	// set only if RoutingType == 0.
	SourceRoutingIPs []net.IP
	// Data is the type-specific data after the first 8 bytes of the header,
	// set only when it was not decoded into SourceRoutingIPs.
	Data []byte
}

// LayerType returns LayerTypeIPv6Routing.
func (i *IPv6Routing) LayerType() gopacket.LayerType { return LayerTypeIPv6Routing }

// SerializeTo implementation according to gopacket.SerializableLayer
func (i *IPv6Routing) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	const ipv6HeaderBaseLen = 8
	totalLen := ipv6HeaderBaseLen + len(i.SourceRoutingIPs)*net.IPv6len + len(i.Data)
	if totalLen%ipv6HeaderBaseLen != 0 {
		return errors.New("IPv6Routing actual length must be multiple of 8")
	}
	hdrExtLen := (totalLen - ipv6HeaderBaseLen) / ipv6HeaderBaseLen
	if totalLen > ipv6MaxExtensionLength {
		return fmt.Errorf("IPv6Routing actual length %d exceeds maximum of %d", totalLen, ipv6MaxExtensionLength)
	}

	bytes, err := b.PrependBytes(totalLen)
	if err != nil {
		return err
	}
	bytes[0] = byte(i.ipv6ExtensionBase.NextHeader)
	bytes[1] = byte(hdrExtLen)
	bytes[2] = i.RoutingType
	bytes[3] = i.SegmentsLeft
	copy(bytes[4:8], i.Reserved)
	for i, ip := range i.SourceRoutingIPs {
		offset := 8 + i*16
		copy(bytes[offset:offset+16], ip.To16())
	}
	copy(bytes[totalLen-len(i.Data):], i.Data)
	return nil
}

func decodeIPv6Routing(data []byte, p gopacket.PacketBuilder) error {
	base, err := decodeIPv6ExtensionBase(data, p)
	if err != nil {
		return err
	}
	i := &IPv6Routing{
		ipv6ExtensionBase: base,
		RoutingType:       data[2],
		SegmentsLeft:      data[3],
		Reserved:          data[4:8],
	}
	// Where the next header starts does not depend on the routing type, and
	// a receiver skips a routing header it cannot process when SegmentsLeft
	// is 0 (RFC 8200 4.4), so type-specific data we cannot decode must not
	// stop the rest of the packet from being decoded.
	if i.RoutingType == 0 && (i.ActualLength-8)%16 == 0 { // Source routing
		for d := i.Contents[8:]; len(d) >= 16; d = d[16:] {
			i.SourceRoutingIPs = append(i.SourceRoutingIPs, net.IP(d[:16]))
		}
	} else {
		i.Data = i.Contents[8:]
	}
	p.AddLayer(i)
	return p.NextDecoder(i.NextHeader)
}

// finalDstIP returns the address the packet is finally delivered to, which
// the transport pseudo-header uses (RFC 8200 8.1). While a Routing header
// has segments left, DstIP is only the next waypoint and the final
// destination is in the header: the last address for types 0 and 2, the
// first segment for type 4. The walk reads the decoded Payload, so a
// hand-built IPv6 layer without one sums DstIP.
func (ipv6 *IPv6) finalDstIP() net.IP {
	const (
		routingTypeSource   = 0
		routingTypeMobile   = 2
		routingTypeSegment  = 4
		routingHeaderMinLen = 8
	)
	nh := ipv6.NextHeader
	if ipv6.HopByHop != nil {
		nh = ipv6.HopByHop.NextHeader
	}
	data := ipv6.Payload
	for nh == IPProtocolIPv6HopByHop || nh == IPProtocolIPv6Destination || nh == IPProtocolIPv6Routing {
		base, err := decodeIPv6ExtensionBase(data, gopacket.NilDecodeFeedback)
		if err != nil {
			break
		}
		if nh == IPProtocolIPv6Routing && data[3] > 0 {
			addresses := (base.ActualLength - routingHeaderMinLen) / net.IPv6len
			if addresses == 0 {
				break
			}
			switch data[2] {
			case routingTypeSource, routingTypeMobile:
				last := routingHeaderMinLen + (addresses-1)*net.IPv6len
				return net.IP(data[last : last+net.IPv6len])
			case routingTypeSegment:
				return net.IP(data[routingHeaderMinLen : routingHeaderMinLen+net.IPv6len])
			}
			break
		}
		nh = base.NextHeader
		data = base.Payload
	}
	return ipv6.DstIP
}

// IPv6Fragment is the IPv6 fragment header, used for packet
// fragmentation/defragmentation.
type IPv6Fragment struct {
	BaseLayer
	NextHeader IPProtocol
	// Reserved1 is bits [8-16), from least to most significant, 0-indexed
	Reserved1      uint8
	FragmentOffset uint16
	// Reserved2 is bits [29-31), from least to most significant, 0-indexed
	Reserved2      uint8
	MoreFragments  bool
	Identification uint32
}

func (i *IPv6Fragment) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	data, err := b.PrependBytes(8)
	if err != nil {
		return err
	}

	data[0] = uint8(i.NextHeader)
	data[1] = i.Reserved1
	binary.BigEndian.PutUint16(data[2:4], i.FragmentOffset<<3)
	data[3] = data[3] | ((i.Reserved2 << 1) & 0x6)
	if i.MoreFragments {
		data[3] = data[3] | 0x1
	}
	binary.BigEndian.PutUint32(data[4:8], i.Identification)
	return nil
}

// LayerType returns LayerTypeIPv6Fragment.
func (i *IPv6Fragment) LayerType() gopacket.LayerType { return LayerTypeIPv6Fragment }

// DecodeFromBytes implementation according to gopacket.DecodingLayer
func (i *IPv6Fragment) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 8 {
		df.SetTruncated()
		return fmt.Errorf("Invalid ip6-fragment header. Length %d less than 8", len(data))
	}
	*i = IPv6Fragment{
		BaseLayer:      BaseLayer{data[:8], data[8:]},
		NextHeader:     IPProtocol(data[0]),
		Reserved1:      data[1],
		FragmentOffset: binary.BigEndian.Uint16(data[2:4]) >> 3,
		Reserved2:      data[3] & 0x6 >> 1,
		MoreFragments:  data[3]&0x1 != 0,
		Identification: binary.BigEndian.Uint32(data[4:8]),
	}
	return nil
}

// CanDecode implementation according to gopacket.DecodingLayer
func (i *IPv6Fragment) CanDecode() gopacket.LayerClass {
	return LayerTypeIPv6Fragment
}

// NextLayerType implementation according to gopacket.DecodingLayer. The
// data behind a fragment header is a piece of the original packet, so it
// is a Fragment as it is for IPv4; only an atomic fragment (offset 0, no
// more fragments) carries the header named by NextHeader.
func (i *IPv6Fragment) NextLayerType() gopacket.LayerType {
	if i.FragmentOffset != 0 || i.MoreFragments {
		return gopacket.LayerTypeFragment
	}
	return i.NextHeader.LayerType()
}

func decodeIPv6Fragment(data []byte, p gopacket.PacketBuilder) error {
	i := &IPv6Fragment{}
	if err := i.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(i)
	return p.NextDecoder(gopacket.DecodeFragment)
}

// IPv6DestinationOption is a TLV option present in an IPv6 destination options extension.
type IPv6DestinationOption ipv6HeaderTLVOption

// IPv6Destination is the IPv6 destination options header.
type IPv6Destination struct {
	ipv6ExtensionBase
	Options []*IPv6DestinationOption
}

// LayerType returns LayerTypeIPv6Destination.
func (i *IPv6Destination) LayerType() gopacket.LayerType { return LayerTypeIPv6Destination }

// DecodeFromBytes implementation according to gopacket.DecodingLayer
func (i *IPv6Destination) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// start from a clean layer: DecodingLayerParser reuses one per packet
	*i = IPv6Destination{}

	var err error
	i.ipv6ExtensionBase, err = decodeIPv6ExtensionBase(data, df)
	if err != nil {
		return err
	}
	offset := 2
	for offset < i.ActualLength {
		opt, err := decodeIPv6HeaderTLVOption(data[offset:i.ActualLength], df)
		if err != nil {
			return err
		}
		i.Options = append(i.Options, (*IPv6DestinationOption)(opt))
		offset += opt.ActualLength
	}
	return nil
}

func decodeIPv6Destination(data []byte, p gopacket.PacketBuilder) error {
	i := &IPv6Destination{}
	err := i.DecodeFromBytes(data, p)
	p.AddLayer(i)
	if err != nil {
		return err
	}
	return p.NextDecoder(i.NextHeader)
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (i *IPv6Destination) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	var bytes []byte
	var err error

	o := make([]*ipv6HeaderTLVOption, 0, len(i.Options))
	for _, v := range i.Options {
		o = append(o, (*ipv6HeaderTLVOption)(v))
	}

	l := serializeIPv6HeaderTLVOptions(nil, o, opts.FixLengths)
	bytes, err = b.PrependBytes(l)
	if err != nil {
		return err
	}
	serializeIPv6HeaderTLVOptions(bytes, o, opts.FixLengths)

	length := len(bytes) + 2
	if length%8 != 0 {
		return errors.New("IPv6Destination actual length must be multiple of 8")
	}
	if length > ipv6MaxExtensionLength {
		return fmt.Errorf("IPv6Destination actual length %d exceeds maximum of %d", length, ipv6MaxExtensionLength)
	}
	bytes, err = b.PrependBytes(2)
	if err != nil {
		return err
	}
	bytes[0] = uint8(i.NextHeader)
	if opts.FixLengths {
		i.HeaderLength = uint8((length / 8) - 1)
	}
	bytes[1] = uint8(i.HeaderLength)
	return nil
}

func checkIPv6Address(addr net.IP) error {
	if len(addr) == net.IPv6len {
		return nil
	}
	if len(addr) == net.IPv4len {
		return errors.New("address is IPv4")
	}
	return fmt.Errorf("wrong length of %d bytes instead of %d", len(addr), net.IPv6len)
}

// AddressTo16 ensures IPv6.SrcIP and IPv6.DstIP are actually IPv6 addresses (i.e. 16 byte addresses)
func (ipv6 *IPv6) AddressTo16() error {
	if err := checkIPv6Address(ipv6.SrcIP); err != nil {
		return fmt.Errorf("Invalid source IPv6 address (%s)", err)
	}
	if err := checkIPv6Address(ipv6.DstIP); err != nil {
		return fmt.Errorf("Invalid destination IPv6 address (%s)", err)
	}
	return nil
}
