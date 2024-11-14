// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
)

// TCP is the layer for TCP headers.
type TCP struct {
	BaseLayer
	SrcPort, DstPort                           TCPPort
	Seq                                        uint32
	Ack                                        uint32
	DataOffset                                 uint8
	FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS bool
	Window                                     uint16
	Checksum                                   uint16
	Urgent                                     uint16
	sPort, dPort                               []byte
	Options                                    []TCPOption
	Padding                                    []byte
	opts                                       [4]TCPOption
	Multipath                                  bool
	tcpipchecksum
}

// TCPOptionKind represents a TCP option code.
type TCPOptionKind uint8

// TCP Option Kind constonts from https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xml#tcp-parameters-1
const (
	TCPOptionKindEndList                         = 0
	TCPOptionKindNop                             = 1
	TCPOptionKindMSS                             = 2  // len = 4
	TCPOptionKindWindowScale                     = 3  // len = 3
	TCPOptionKindSACKPermitted                   = 4  // len = 2
	TCPOptionKindSACK                            = 5  // len = n
	TCPOptionKindEcho                            = 6  // len = 6, obsolete
	TCPOptionKindEchoReply                       = 7  // len = 6, obsolete
	TCPOptionKindTimestamps                      = 8  // len = 10
	TCPOptionKindPartialOrderConnectionPermitted = 9  // len = 2, obsolete
	TCPOptionKindPartialOrderServiceProfile      = 10 // len = 3, obsolete
	TCPOptionKindCC                              = 11 // obsolete
	TCPOptionKindCCNew                           = 12 // obsolete
	TCPOptionKindCCEcho                          = 13 // obsolete
	TCPOptionKindAltChecksum                     = 14 // len = 3, obsolete
	TCPOptionKindAltChecksumData                 = 15 // len = n, obsolete
	TCPOptionKindMultipathTCP                    = 30
)

func (k TCPOptionKind) String() string {
	switch k {
	case TCPOptionKindEndList:
		return "EndList"
	case TCPOptionKindNop:
		return "NOP"
	case TCPOptionKindMSS:
		return "MSS"
	case TCPOptionKindWindowScale:
		return "WindowScale"
	case TCPOptionKindSACKPermitted:
		return "SACKPermitted"
	case TCPOptionKindSACK:
		return "SACK"
	case TCPOptionKindEcho:
		return "Echo"
	case TCPOptionKindEchoReply:
		return "EchoReply"
	case TCPOptionKindTimestamps:
		return "Timestamps"
	case TCPOptionKindPartialOrderConnectionPermitted:
		return "PartialOrderConnectionPermitted"
	case TCPOptionKindPartialOrderServiceProfile:
		return "PartialOrderServiceProfile"
	case TCPOptionKindCC:
		return "CC"
	case TCPOptionKindCCNew:
		return "CCNew"
	case TCPOptionKindCCEcho:
		return "CCEcho"
	case TCPOptionKindAltChecksum:
		return "AltChecksum"
	case TCPOptionKindAltChecksumData:
		return "AltChecksumData"
	case TCPOptionKindMultipathTCP:
		return "MultipathTCP"
	default:
		return fmt.Sprintf("Unknown(%d)", k)
	}
}

// TCPOption are the possible TCP and MPTCP Options
type TCPOption struct {
	OptionType            TCPOptionKind
	OptionLength          uint8
	OptionData            []byte
	OptionMultipath       MPTCPSubtype
	OptionMPTCPMpCapable  *MPCapable
	OptionMPTCPDss        *Dss
	OptionMPTCPMpJoin     *MPJoin
	OptionMPTCPMpPrio     *MPPrio
	OptionMPTCPAddAddr    *AddAddr
	OptionMTCPRemAddr     *RemAddr
	OptionMTCPMPFastClose *MPFClose
	OptionMPTCPMPTcpRst   *MPTcpRst
	OptionMTCPMPFail      *MPFail
}

func (t TCPOption) String() string {
	hd := hex.EncodeToString(t.OptionData)
	if len(hd) > 0 {
		hd = " 0x" + hd
	}
	switch t.OptionType {
	case TCPOptionKindMSS:
		if len(t.OptionData) >= 2 {
			return fmt.Sprintf("TCPOption(%s:%v%s)",
				t.OptionType,
				binary.BigEndian.Uint16(t.OptionData),
				hd)
		}

	case TCPOptionKindTimestamps:
		if len(t.OptionData) == 8 {
			return fmt.Sprintf("TCPOption(%s:%v/%v%s)",
				t.OptionType,
				binary.BigEndian.Uint32(t.OptionData[:4]),
				binary.BigEndian.Uint32(t.OptionData[4:8]),
				hd)
		}

	case TCPOptionKindMultipathTCP:
		switch t.OptionMultipath {
		case MPTCPSubtypeMPCAPABLE:
			return fmt.Sprintf("MPTCPOption(%s Version %v)",
				t.OptionMultipath,
				t.OptionMPTCPMpCapable.Version)
		case MPTCPSubtypeMPJOIN:
			return fmt.Sprintf("MPTCPOption(%s Backup %v;Address ID %v)",
				t.OptionMultipath,
				t.OptionMPTCPMpJoin.Backup,
				t.OptionMPTCPMpJoin.AddrID)
		case MPTCPSubtypeDSS:
			return fmt.Sprintf("MPTCPOption(%s)",
				t.OptionMultipath)
		case MPTCPSubtypeMPPRIO:
			return fmt.Sprintf("MPTCPOption(%s Backup %v;Address ID %v)",
				t.OptionMultipath,
				t.OptionMPTCPMpPrio.Backup,
				t.OptionMPTCPMpPrio.AddrID)
		case MPTCPSubtypeADDADDR:
			return fmt.Sprintf("MPTCPOption(%s Address ID %v;Address %v;Port %v)",
				t.OptionMultipath,
				t.OptionMPTCPAddAddr.AddrID,
				t.OptionMPTCPAddAddr.Address,
				t.OptionMPTCPAddAddr.Port)
		case MPTCPSubtypeREMOVEADDR:
			return fmt.Sprintf("MPTCPOption(%s Address ID %v)",
				t.OptionMultipath,
				t.OptionMTCPRemAddr.AddrIDs)
		case MPTCPSubtypeMPFASTCLOSE:
			return fmt.Sprintf("MPTCPOption(%s)",
				t.OptionMultipath)
		case MPTCPSubtypeMPTCPRST:
			return fmt.Sprintf("MPTCPOption(%s Transient %v; Reason %v)",
				t.OptionMultipath,
				t.OptionMPTCPMPTcpRst.T,
				t.OptionMPTCPMPTcpRst.Reason)
		case MPTCPSubtypeMPFAIL:
			return fmt.Sprintf("MPTCPOption(%s)",
				t.OptionMultipath)
		}
	}
	return fmt.Sprintf("TCPOption(%s:%s)", t.OptionType, hd)
}

// LayerType returns gopacket.LayerTypeTCP
func (t *TCP) LayerType() gopacket.LayerType { return LayerTypeTCP }

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (t *TCP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	var optionLength int
	for _, o := range t.Options {
		switch o.OptionType {
		case 0, 1:
			optionLength += 1
		default:
			optionLength += 2 + len(o.OptionData)
		}
	}
	if opts.FixLengths {
		if rem := optionLength % 4; rem != 0 {
			t.Padding = lotsOfZeros[:4-rem]
		}
		t.DataOffset = uint8((len(t.Padding) + optionLength + 20) / 4)
	}
	bytes, err := b.PrependBytes(20 + optionLength + len(t.Padding))
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, uint16(t.SrcPort))
	binary.BigEndian.PutUint16(bytes[2:], uint16(t.DstPort))
	binary.BigEndian.PutUint32(bytes[4:], t.Seq)
	binary.BigEndian.PutUint32(bytes[8:], t.Ack)
	binary.BigEndian.PutUint16(bytes[12:], t.flagsAndOffset())
	binary.BigEndian.PutUint16(bytes[14:], t.Window)
	binary.BigEndian.PutUint16(bytes[18:], t.Urgent)
	start := 20
	for _, o := range t.Options {
		bytes[start] = byte(o.OptionType)
		switch o.OptionType {
		case 0, 1:
			start++
		default:
			if opts.FixLengths {
				o.OptionLength = uint8(len(o.OptionData) + 2)
			}
			bytes[start+1] = o.OptionLength
			copy(bytes[start+2:start+len(o.OptionData)+2], o.OptionData)
			start += len(o.OptionData) + 2
		}
	}
	copy(bytes[start:], t.Padding)
	if opts.ComputeChecksums {
		// zero out checksum bytes in current serialization.
		bytes[16] = 0
		bytes[17] = 0
		csum, err := t.computeChecksum(b.Bytes(), IPProtocolTCP)
		if err != nil {
			return err
		}
		t.Checksum = gopacket.FoldChecksum(csum)
	}
	binary.BigEndian.PutUint16(bytes[16:], t.Checksum)
	return nil
}

func (t *TCP) ComputeChecksum() (uint16, error) {
	csum, err := t.computeChecksum(append(t.Contents, t.Payload...), IPProtocolTCP)
	if err != nil {
		return 0, err
	}
	return gopacket.FoldChecksum(csum), nil
}

func (t *TCP) flagsAndOffset() uint16 {
	f := uint16(t.DataOffset) << 12
	if t.FIN {
		f |= 0x0001
	}
	if t.SYN {
		f |= 0x0002
	}
	if t.RST {
		f |= 0x0004
	}
	if t.PSH {
		f |= 0x0008
	}
	if t.ACK {
		f |= 0x0010
	}
	if t.URG {
		f |= 0x0020
	}
	if t.ECE {
		f |= 0x0040
	}
	if t.CWR {
		f |= 0x0080
	}
	if t.NS {
		f |= 0x0100
	}
	return f
}

func (tcp *TCP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 20 {
		df.SetTruncated()
		return fmt.Errorf("Invalid TCP header. Length %d less than 20", len(data))
	}
	tcp.SrcPort = TCPPort(binary.BigEndian.Uint16(data[0:2]))
	tcp.sPort = data[0:2]
	tcp.DstPort = TCPPort(binary.BigEndian.Uint16(data[2:4]))
	tcp.dPort = data[2:4]
	tcp.Seq = binary.BigEndian.Uint32(data[4:8])
	tcp.Ack = binary.BigEndian.Uint32(data[8:12])
	tcp.DataOffset = data[12] >> 4
	tcp.FIN = data[13]&0x01 != 0
	tcp.SYN = data[13]&0x02 != 0
	tcp.RST = data[13]&0x04 != 0
	tcp.PSH = data[13]&0x08 != 0
	tcp.ACK = data[13]&0x10 != 0
	tcp.URG = data[13]&0x20 != 0
	tcp.ECE = data[13]&0x40 != 0
	tcp.CWR = data[13]&0x80 != 0
	tcp.NS = data[12]&0x01 != 0
	tcp.Window = binary.BigEndian.Uint16(data[14:16])
	tcp.Checksum = binary.BigEndian.Uint16(data[16:18])
	tcp.Urgent = binary.BigEndian.Uint16(data[18:20])
	if tcp.Options == nil {
		// Pre-allocate to avoid allocating a slice.
		tcp.Options = tcp.opts[:0]
	} else {
		tcp.Options = tcp.Options[:0]
	}
	tcp.Padding = tcp.Padding[:0]
	if tcp.DataOffset < 5 {
		return fmt.Errorf("Invalid TCP data offset %d < 5", tcp.DataOffset)
	}
	dataStart := int(tcp.DataOffset) * 4
	if dataStart > len(data) {
		df.SetTruncated()
		tcp.Payload = nil
		tcp.Contents = data
		return errors.New("TCP data offset greater than packet length")
	}
	tcp.Contents = data[:dataStart]
	tcp.Payload = data[dataStart:]
	// From here on, data points just to the header options.
	data = data[20:dataStart]
OPTIONS:
	for len(data) > 0 {
		tcp.Options = append(tcp.Options, TCPOption{OptionType: TCPOptionKind(data[0])})
		opt := &tcp.Options[len(tcp.Options)-1]
		switch opt.OptionType {
		case TCPOptionKindEndList: // End of options
			opt.OptionLength = 1
			tcp.Padding = data[1:]
			break OPTIONS
		case TCPOptionKindNop: // 1 byte padding
			opt.OptionLength = 1
		case TCPOptionKindMultipathTCP:
			tcp.Multipath = true
			opt.OptionLength = data[1]
			opt.OptionMultipath = MPTCPSubtype(data[2] >> 4)
			switch opt.OptionMultipath {
			case MPTCPSubtypeMPCAPABLE:
				if opt.OptionLength != OptionLenMpCapableSyn && opt.OptionLength != OptionLenMpCapableSynAck && opt.OptionLength != OptionLenMpCapableAck && opt.OptionLength != OptionLenMpCapableAckData && opt.OptionLength != OptionLenMpCapableAckDataCSum {
					return fmt.Errorf("MP_CAPABLE bad option length %d", opt.OptionLength)
				}
				opt.OptionMPTCPMpCapable = &MPCapable{
					Version: data[2] & 0x0F,
					A:       data[3]&0x80 != 0,
					B:       data[3]&0x40 != 0,
					C:       data[3]&0x20 != 0,
					D:       data[3]&0x10 != 0,
					E:       data[3]&0x08 != 0,
					F:       data[3]&0x04 != 0,
					G:       data[3]&0x02 != 0,
					H:       data[3]&0x01 != 0,
				}
				if opt.OptionLength >= OptionLenMpCapableSynAck {
					opt.OptionMPTCPMpCapable.SendKey = data[4:12]
				}
				if opt.OptionLength >= OptionLenMpCapableAck {
					opt.OptionMPTCPMpCapable.ReceivKey = data[12:20]
				}
				if opt.OptionLength >= OptionLenMpCapableAckData {
					opt.OptionMPTCPMpCapable.DataLength = binary.BigEndian.Uint16(data[20:22])
				}
				if opt.OptionLength == OptionLenMpCapableAckDataCSum {
					opt.OptionMPTCPMpCapable.Checksum = binary.BigEndian.Uint16(data[22:24])
				}
			case MPTCPSubtypeMPJOIN:
				if opt.OptionLength != OptionLenMpJoinSyn && opt.OptionLength != OptionLenMpJoinSynAck && opt.OptionLength != OptionLenMpJoinAck {
					return fmt.Errorf("MP_JOIN bad option length %d", opt.OptionLength)
				}
				switch opt.OptionLength {
				case OptionLenMpJoinSyn:
					opt.OptionMPTCPMpJoin = &MPJoin{
						Backup:      data[2]&0x01 != 0,
						AddrID:      data[3],
						ReceivToken: binary.BigEndian.Uint32(data[4:8]),
						SendRandNum: binary.BigEndian.Uint32(data[8:12]),
					}
				case OptionLenMpJoinSynAck:
					opt.OptionMPTCPMpJoin = &MPJoin{
						Backup:      data[2]&0x01 != 0,
						AddrID:      data[3],
						SendHMAC:    data[4:12],
						SendRandNum: binary.BigEndian.Uint32(data[12:16]),
					}
				case OptionLenMpJoinAck:
					opt.OptionMPTCPMpJoin = &MPJoin{
						SendHMAC: data[4:24],
					}
				}
			case MPTCPSubtypeDSS:
				opt.OptionMPTCPDss = &Dss{
					F: data[3]&0x10 != 0,
					m: data[3]&0x08 != 0,
					M: data[3]&0x04 != 0,
					a: data[3]&0x02 != 0,
					A: data[3]&0x01 != 0,
				}
				if opt.OptionLength != optionMptcpDsslen(opt.OptionMPTCPDss, false) && opt.OptionLength != optionMptcpDsslen(opt.OptionMPTCPDss, true) {
					return fmt.Errorf("DSS bad option length %d", opt.OptionLength)
				}
				var lenOpt uint8 = 4
				if opt.OptionMPTCPDss.A { // Data ACK present
					if opt.OptionMPTCPDss.a { // Data ACK is 8 octets
						opt.OptionMPTCPDss.DataAck = data[lenOpt : lenOpt+OptionLenDssAck64]
						lenOpt += OptionLenDssAck64
					} else {
						opt.OptionMPTCPDss.DataAck = data[lenOpt : lenOpt+OptionLenDssAck]
						lenOpt += OptionLenDssAck
					}
				}
				if opt.OptionMPTCPDss.M { // Data Sequence Number (DSN), Subflow Sequence Number (SSN), Data-Level Length, and Checksum (if negotiated) present
					if opt.OptionMPTCPDss.m { // Data Sequence Number is 8 octets
						opt.OptionMPTCPDss.DSN = data[lenOpt : lenOpt+OptionLenDssDSN64]
						lenOpt += OptionLenDssDSN64
					} else {
						opt.OptionMPTCPDss.DSN = data[lenOpt : lenOpt+OptionLenDssDSN]
						lenOpt += OptionLenDssDSN
					}
					opt.OptionMPTCPDss.SSN = binary.BigEndian.Uint32(data[lenOpt : lenOpt+OptionLenDssSSN])
					lenOpt += OptionLenDssSSN
					opt.OptionMPTCPDss.DataLength = binary.BigEndian.Uint16(data[lenOpt : lenOpt+OptionLenDssDataLen])
					lenOpt += OptionLenDssDataLen
					if opt.OptionLength-lenOpt == 2 { // Checksum present
						opt.OptionMPTCPDss.Checksum = binary.BigEndian.Uint16(data[lenOpt : lenOpt+OptionLenDssCSum])
					}
				}
			case MPTCPSubtypeADDADDR:
				var mptcpVer uint8
				var bitE bool
				lenOpt := opt.OptionLength

				if data[2]&0x0F > 1 {
					mptcpVer = MptcpVersion0
				} else {
					mptcpVer = MptcpVersion1
					bitE = data[2]&0x01 != 0
				}
				if !isValidOptionMptcpAddAddrlen(opt.OptionLength, mptcpVer, bitE) {
					return fmt.Errorf("ADD_ADDR bad option length %d", opt.OptionLength)
				}
				switch mptcpVer {
				case MptcpVersion0:
					opt.OptionMPTCPAddAddr = &AddAddr{
						IPVer:  data[2] & 0x0F,
						AddrID: data[3],
					}
				case MptcpVersion1:
					opt.OptionMPTCPAddAddr = &AddAddr{
						E:      data[2]&0x01 != 0,
						AddrID: data[3],
					}
					if !opt.OptionMPTCPAddAddr.E {
						opt.OptionMPTCPAddAddr.SendHMAC = data[opt.OptionLength-8:]
						lenOpt -= OptionLenAddAddrHmac
					}
				}
				switch lenOpt {
				case OptionLenAddAddrv4:
					opt.OptionMPTCPAddAddr.Address = data[4:8]
				case OptionLenAddAddrv4 + OptionLenAddAddrPort:
					opt.OptionMPTCPAddAddr.Address = data[4:8]
					opt.OptionMPTCPAddAddr.Port = binary.BigEndian.Uint16(data[8:10])
				case OptionLenAddAddrv6:
					opt.OptionMPTCPAddAddr.Address = data[4:20]
				case OptionLenAddAddrv6 + OptionLenAddAddrPort:
					opt.OptionMPTCPAddAddr.Address = data[4:20]
					opt.OptionMPTCPAddAddr.Port = binary.BigEndian.Uint16(data[20:22])
				}
			case MPTCPSubtypeREMOVEADDR:
				if opt.OptionLength < OptionLenRemAddr {
					return fmt.Errorf("Rem_ADDR bad option length %d", opt.OptionLength)
				}
				var addrIds []uint8
				var n uint8
				for n = 0; n < opt.OptionLength-3; n++ {
					addrIds = append(addrIds, data[3+n])
				}
				opt.OptionMTCPRemAddr = &RemAddr{
					AddrIDs: addrIds,
				}
			case MPTCPSubtypeMPPRIO:
				if opt.OptionLength != OptionLenMpPrio && opt.OptionLength != OptionLenMpPrioAddr {
					return fmt.Errorf("MP_PRIO bad option length %d", opt.OptionLength)
				}
				opt.OptionMPTCPMpPrio = &MPPrio{
					Backup: data[2]&0x01 != 0,
				}
				if opt.OptionLength == OptionLenMpPrioAddr {
					opt.OptionMPTCPMpPrio.AddrID = data[3]
				}
			case MPTCPSubtypeMPFAIL:
				if opt.OptionLength != OptionLenMpFail {
					return fmt.Errorf("MP_FAIL bad option length %d", opt.OptionLength)
				}
				opt.OptionMTCPMPFail = &MPFail{
					DSN: binary.BigEndian.Uint64(data[4:OptionLenMpFail]),
				}

			case MPTCPSubtypeMPFASTCLOSE:
				if opt.OptionLength != OptionLenMpFClose {
					return fmt.Errorf("MP_FASTCLOSE bad option length %d", opt.OptionLength)
				}
				opt.OptionMTCPMPFastClose = &MPFClose{
					ReceivKey: data[4:OptionLenMpFClose],
				}
			case MPTCPSubtypeMPTCPRST:
				if opt.OptionLength != OptionLenMpTcpRst {
					return fmt.Errorf("MP_TCPRST bad option length %d", opt.OptionLength)
				}
				opt.OptionMPTCPMPTcpRst = &MPTcpRst{
					U:      data[2]&0x08 != 0,
					V:      data[2]&0x04 != 0,
					W:      data[2]&0x02 != 0,
					T:      data[2]&0x01 != 0,
					Reason: data[3],
				}
			}
		default:
			if len(data) < 2 {
				df.SetTruncated()
				return fmt.Errorf("Invalid TCP option length. Length %d less than 2", len(data))
			}
			opt.OptionLength = data[1]
			if opt.OptionLength < 2 {
				return fmt.Errorf("Invalid TCP option length %d < 2", opt.OptionLength)
			} else if int(opt.OptionLength) > len(data) {
				df.SetTruncated()
				return fmt.Errorf("Invalid TCP option length %d exceeds remaining %d bytes", opt.OptionLength, len(data))
			}
			opt.OptionData = data[2:opt.OptionLength]
		}
		data = data[opt.OptionLength:]
	}
	return nil
}

func optionMptcpDsslen(OptionMPTCPDss *Dss, csum bool) uint8 {
	var len uint8 = 4
	if OptionMPTCPDss.A { // Data ACK
		len += 4
		if OptionMPTCPDss.a {
			len += 4
		} // Data ACK 8 octets
	}
	if OptionMPTCPDss.M { // DSN (4)+ SSN (4) + Data-Level Length (2) = 10
		len += 10
		if OptionMPTCPDss.m {
			len += 4
		} // DSN 8 octets
		if csum {
			len += 2
		}
	}
	return len
}

func isValidOptionMptcpAddAddrlen(length uint8, mptcpVer uint8, hmac bool) bool {
	var ret bool
	switch mptcpVer {
	case MptcpVersion0:
		ret = length == OptionLenAddAddrv4 || length == OptionLenAddAddrv4+OptionLenAddAddrPort || length == OptionLenAddAddrv6 || length == OptionLenAddAddrv6+OptionLenAddAddrPort
	case MptcpVersion1:
		if !hmac {
			length -= OptionLenAddAddrHmac
		}
		ret = length == OptionLenAddAddrv4 || length == OptionLenAddAddrv4+OptionLenAddAddrPort || length == OptionLenAddAddrv6 || length == OptionLenAddAddrv6+OptionLenAddAddrPort
	}
	return ret
}

func (t *TCP) CanDecode() gopacket.LayerClass {
	return LayerTypeTCP
}

func (t *TCP) NextLayerType() gopacket.LayerType {
	lt := t.DstPort.LayerType()
	if lt == gopacket.LayerTypePayload {
		lt = t.SrcPort.LayerType()
	}
	return lt
}

func decodeTCP(data []byte, p gopacket.PacketBuilder) error {
	tcp := &TCP{}
	err := tcp.DecodeFromBytes(data, p)
	p.AddLayer(tcp)
	p.SetTransportLayer(tcp)
	if err != nil {
		return err
	}
	if p.DecodeOptions().DecodeStreamsAsDatagrams {
		return p.NextDecoder(tcp.NextLayerType())
	} else {
		return p.NextDecoder(gopacket.LayerTypePayload)
	}
}

func (t *TCP) TransportFlow() gopacket.Flow {
	return gopacket.NewFlow(EndpointTCPPort, t.sPort, t.dPort)
}

// For testing only
func (t *TCP) SetInternalPortsForTesting() {
	t.sPort = make([]byte, 2)
	t.dPort = make([]byte, 2)
	binary.BigEndian.PutUint16(t.sPort, uint16(t.SrcPort))
	binary.BigEndian.PutUint16(t.dPort, uint16(t.DstPort))
}

func (t *TCP) VerifyChecksum() (error, gopacket.ChecksumVerificationResult) {
	bytes := append(t.Contents, t.Payload...)

	existing := t.Checksum
	verification, err := t.computeChecksum(bytes, IPProtocolTCP)
	if err != nil {
		return err, gopacket.ChecksumVerificationResult{}
	}
	correct := gopacket.FoldChecksum(verification - uint32(existing))
	return nil, gopacket.ChecksumVerificationResult{
		Valid:   correct == existing,
		Correct: uint32(correct),
		Actual:  uint32(existing),
	}
}
