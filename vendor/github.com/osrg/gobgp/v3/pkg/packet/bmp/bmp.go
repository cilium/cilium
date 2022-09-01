// Copyright (C) 2014,2015 Nippon Telegraph and Telephone Corporation.
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

package bmp

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

type BMPHeader struct {
	Version uint8
	Length  uint32
	Type    uint8
}

const (
	BMP_VERSION          = 3
	BMP_HEADER_SIZE      = 6
	BMP_PEER_HEADER_SIZE = 42
)

const (
	BMP_DEFAULT_PORT = 11019
)

const (
	BMP_PEER_TYPE_GLOBAL uint8 = iota
	BMP_PEER_TYPE_L3VPN
	BMP_PEER_TYPE_LOCAL
	BMP_PEER_TYPE_LOCAL_RIB
)

const (
	BMP_PEER_FLAG_IPV6        = 1 << 7
	BMP_PEER_FLAG_POST_POLICY = 1 << 6
	BMP_PEER_FLAG_TWO_AS      = 1 << 5
	BMP_PEER_FLAG_ADJ_RIB_TYP = 1 << 4
)

func makeIP(data []byte) net.IP {
	ip := make(net.IP, len(data))
	copy(ip, data)
	return ip
}

func (h *BMPHeader) DecodeFromBytes(data []byte) error {
	h.Version = data[0]
	if data[0] != BMP_VERSION {
		return fmt.Errorf("error version")
	}
	h.Length = binary.BigEndian.Uint32(data[1:5])
	h.Type = data[5]
	return nil
}

func (h *BMPHeader) Serialize() ([]byte, error) {
	buf := make([]byte, BMP_HEADER_SIZE)
	buf[0] = h.Version
	binary.BigEndian.PutUint32(buf[1:], h.Length)
	buf[5] = h.Type
	return buf, nil
}

type BMPPeerHeader struct {
	PeerType          uint8
	Flags             uint8
	PeerDistinguisher uint64
	PeerAddress       net.IP
	PeerAS            uint32
	PeerBGPID         net.IP
	Timestamp         float64
}

func NewBMPPeerHeader(t uint8, flags uint8, dist uint64, address string, as uint32, id string, stamp float64) *BMPPeerHeader {
	h := &BMPPeerHeader{
		PeerType:          t,
		Flags:             flags,
		PeerDistinguisher: dist,
		PeerAS:            as,
		PeerBGPID:         net.ParseIP(id).To4(),
		Timestamp:         stamp,
	}
	if net.ParseIP(address).To4() != nil {
		h.PeerAddress = net.ParseIP(address).To4()
	} else {
		h.PeerAddress = net.ParseIP(address).To16()
		h.Flags |= BMP_PEER_FLAG_IPV6
	}
	return h
}

func (h *BMPPeerHeader) IsPostPolicy() bool {
	if h.Flags&BMP_PEER_FLAG_POST_POLICY != 0 {
		return true
	} else {
		return false
	}
}

func (h *BMPPeerHeader) IsAdjRIBOut() bool {
	return h.Flags&BMP_PEER_FLAG_ADJ_RIB_TYP != 0
}

func (h *BMPPeerHeader) DecodeFromBytes(data []byte) error {
	h.PeerType = data[0]
	h.Flags = data[1]
	h.PeerDistinguisher = binary.BigEndian.Uint64(data[2:10])
	if h.Flags&BMP_PEER_FLAG_IPV6 != 0 {
		h.PeerAddress = makeIP(data[10:26]).To16()
	} else {
		h.PeerAddress = makeIP(data[22:26]).To4()
	}
	h.PeerAS = binary.BigEndian.Uint32(data[26:30])
	h.PeerBGPID = data[30:34]

	timestamp1 := binary.BigEndian.Uint32(data[34:38])
	timestamp2 := binary.BigEndian.Uint32(data[38:42])
	h.Timestamp = float64(timestamp1) + float64(timestamp2)*math.Pow10(-6)
	return nil
}

func (h *BMPPeerHeader) Serialize() ([]byte, error) {
	buf := make([]byte, BMP_PEER_HEADER_SIZE)
	buf[0] = h.PeerType
	buf[1] = h.Flags
	binary.BigEndian.PutUint64(buf[2:10], h.PeerDistinguisher)
	if h.Flags&BMP_PEER_FLAG_IPV6 != 0 {
		copy(buf[10:26], h.PeerAddress)
	} else {
		copy(buf[22:26], h.PeerAddress.To4())
	}
	binary.BigEndian.PutUint32(buf[26:30], h.PeerAS)
	copy(buf[30:34], h.PeerBGPID)
	t1, t2 := math.Modf(h.Timestamp)
	t2 = math.Ceil(t2 * math.Pow10(6))
	binary.BigEndian.PutUint32(buf[34:38], uint32(t1))
	binary.BigEndian.PutUint32(buf[38:42], uint32(t2))
	return buf, nil
}

type BMPRouteMonitoring struct {
	BGPUpdate        *bgp.BGPMessage
	BGPUpdatePayload []byte
}

func NewBMPRouteMonitoring(p BMPPeerHeader, update *bgp.BGPMessage) *BMPMessage {
	return &BMPMessage{
		Header: BMPHeader{
			Version: BMP_VERSION,
			Type:    BMP_MSG_ROUTE_MONITORING,
		},
		PeerHeader: p,
		Body: &BMPRouteMonitoring{
			BGPUpdate: update,
		},
	}
}

func (body *BMPRouteMonitoring) ParseBody(msg *BMPMessage, data []byte) error {
	var err error

	body.BGPUpdate, err = bgp.ParseBGPMessage(data)

	return err
}

func (body *BMPRouteMonitoring) Serialize() ([]byte, error) {
	if body.BGPUpdatePayload != nil {
		return body.BGPUpdatePayload, nil
	}
	return body.BGPUpdate.Serialize()
}

const (
	BMP_STAT_TYPE_REJECTED = iota
	BMP_STAT_TYPE_DUPLICATE_PREFIX
	BMP_STAT_TYPE_DUPLICATE_WITHDRAW
	BMP_STAT_TYPE_INV_UPDATE_DUE_TO_CLUSTER_LIST_LOOP
	BMP_STAT_TYPE_INV_UPDATE_DUE_TO_AS_PATH_LOOP
	BMP_STAT_TYPE_INV_UPDATE_DUE_TO_ORIGINATOR_ID
	BMP_STAT_TYPE_INV_UPDATE_DUE_TO_AS_CONFED_LOOP
	BMP_STAT_TYPE_ADJ_RIB_IN
	BMP_STAT_TYPE_LOC_RIB
	BMP_STAT_TYPE_PER_AFI_SAFI_ADJ_RIB_IN
	BMP_STAT_TYPE_PER_AFI_SAFI_LOC_RIB
	BMP_STAT_TYPE_WITHDRAW_UPDATE
	BMP_STAT_TYPE_WITHDRAW_PREFIX
	BMP_STAT_TYPE_DUPLICATE_UPDATE
	BMP_STAT_TYPE_ADJ_RIB_OUT_PRE_POLICY
	BMP_STAT_TYPE_ADJ_RIB_OUT_POST_POLICY
	BMP_STAT_TYPE_PER_AFI_SAFI_ADJ_RIB_OUT_PRE_POLICY
	BMP_STAT_TYPE_PER_AFI_SAFI_ADJ_RIB_OUT_POST_POLICY
)

type BMPStatsTLVInterface interface {
	ParseValue([]byte) error
	Serialize() ([]byte, error)
}

type BMPStatsTLV struct {
	Type   uint16
	Length uint16
}

type BMPStatsTLV32 struct {
	BMPStatsTLV
	Value uint32
}

func NewBMPStatsTLV32(t uint16, v uint32) *BMPStatsTLV32 {
	return &BMPStatsTLV32{
		BMPStatsTLV: BMPStatsTLV{
			Type:   t,
			Length: 4,
		},
		Value: v,
	}
}

func (s *BMPStatsTLV32) ParseValue(data []byte) error {
	if s.Length != 4 {
		return fmt.Errorf("invalid length: %d bytes (%d bytes expected)", s.Length, 4)
	}
	s.Value = binary.BigEndian.Uint32(data[:4])
	return nil
}

func (s *BMPStatsTLV32) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint16(buf[0:2], s.Type)
	binary.BigEndian.PutUint16(buf[2:4], 4)
	binary.BigEndian.PutUint32(buf[4:8], s.Value)
	return buf, nil
}

type BMPStatsTLV64 struct {
	BMPStatsTLV
	Value uint64
}

func NewBMPStatsTLV64(t uint16, v uint64) *BMPStatsTLV64 {
	return &BMPStatsTLV64{
		BMPStatsTLV: BMPStatsTLV{
			Type:   t,
			Length: 8,
		},
		Value: v,
	}
}

func (s *BMPStatsTLV64) ParseValue(data []byte) error {
	if s.Length != 8 {
		return fmt.Errorf("invalid length: %d bytes (%d bytes expected)", s.Length, 8)
	}
	s.Value = binary.BigEndian.Uint64(data[:8])
	return nil
}

func (s *BMPStatsTLV64) Serialize() ([]byte, error) {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], s.Type)
	binary.BigEndian.PutUint16(buf[2:4], 8)
	binary.BigEndian.PutUint64(buf[4:12], s.Value)
	return buf, nil
}

type BMPStatsTLVPerAfiSafi64 struct {
	BMPStatsTLV
	AFI   uint16
	SAFI  uint8
	Value uint64
}

func NewBMPStatsTLVPerAfiSafi64(t uint16, afi uint16, safi uint8, v uint64) *BMPStatsTLVPerAfiSafi64 {
	return &BMPStatsTLVPerAfiSafi64{
		BMPStatsTLV: BMPStatsTLV{
			Type:   t,
			Length: 11,
		},
		AFI:   afi,
		SAFI:  safi,
		Value: v,
	}
}

func (s *BMPStatsTLVPerAfiSafi64) ParseValue(data []byte) error {
	if s.Length != 11 {
		return fmt.Errorf("invalid length: %d bytes (%d bytes expected)", s.Length, 11)
	}
	s.AFI = binary.BigEndian.Uint16(data[0:2])
	s.SAFI = data[2]
	s.Value = binary.BigEndian.Uint64(data[3:11])
	return nil
}

func (s *BMPStatsTLVPerAfiSafi64) Serialize() ([]byte, error) {
	buf := make([]byte, 15)
	binary.BigEndian.PutUint16(buf[0:2], s.Type)
	binary.BigEndian.PutUint16(buf[2:4], 11)
	binary.BigEndian.PutUint16(buf[4:6], s.AFI)
	buf[6] = s.SAFI
	binary.BigEndian.PutUint64(buf[7:15], s.Value)
	return buf, nil
}

type BMPStatisticsReport struct {
	Count uint32
	Stats []BMPStatsTLVInterface
}

func NewBMPStatisticsReport(p BMPPeerHeader, stats []BMPStatsTLVInterface) *BMPMessage {
	return &BMPMessage{
		Header: BMPHeader{
			Version: BMP_VERSION,
			Type:    BMP_MSG_STATISTICS_REPORT,
		},
		PeerHeader: p,
		Body: &BMPStatisticsReport{
			Count: uint32(len(stats)),
			Stats: stats,
		},
	}
}

func (body *BMPStatisticsReport) ParseBody(msg *BMPMessage, data []byte) error {
	body.Count = binary.BigEndian.Uint32(data[0:4])
	data = data[4:]
	for len(data) >= 4 {
		tl := BMPStatsTLV{
			Type:   binary.BigEndian.Uint16(data[0:2]),
			Length: binary.BigEndian.Uint16(data[2:4]),
		}
		data = data[4:]
		if len(data) < int(tl.Length) {
			return fmt.Errorf("value length is not enough: %d bytes (%d bytes expected)", len(data), tl.Length)
		}
		var s BMPStatsTLVInterface
		switch tl.Type {
		case BMP_STAT_TYPE_ADJ_RIB_IN, BMP_STAT_TYPE_LOC_RIB, BMP_STAT_TYPE_ADJ_RIB_OUT_PRE_POLICY,
			BMP_STAT_TYPE_ADJ_RIB_OUT_POST_POLICY:
			s = &BMPStatsTLV64{BMPStatsTLV: tl}
		case BMP_STAT_TYPE_PER_AFI_SAFI_ADJ_RIB_IN, BMP_STAT_TYPE_PER_AFI_SAFI_LOC_RIB,
			BMP_STAT_TYPE_PER_AFI_SAFI_ADJ_RIB_OUT_PRE_POLICY, BMP_STAT_TYPE_PER_AFI_SAFI_ADJ_RIB_OUT_POST_POLICY:
			s = &BMPStatsTLVPerAfiSafi64{BMPStatsTLV: tl}
		case BMP_STAT_TYPE_REJECTED, BMP_STAT_TYPE_DUPLICATE_PREFIX,
			BMP_STAT_TYPE_DUPLICATE_WITHDRAW, BMP_STAT_TYPE_INV_UPDATE_DUE_TO_CLUSTER_LIST_LOOP,
			BMP_STAT_TYPE_INV_UPDATE_DUE_TO_AS_PATH_LOOP, BMP_STAT_TYPE_INV_UPDATE_DUE_TO_ORIGINATOR_ID,
			BMP_STAT_TYPE_INV_UPDATE_DUE_TO_AS_CONFED_LOOP, BMP_STAT_TYPE_WITHDRAW_UPDATE,
			BMP_STAT_TYPE_WITHDRAW_PREFIX, BMP_STAT_TYPE_DUPLICATE_UPDATE:
			s = &BMPStatsTLV32{BMPStatsTLV: tl}
		default:
			switch tl.Length {
			case 4:
				s = &BMPStatsTLV32{BMPStatsTLV: tl}
			case 8:
				s = &BMPStatsTLV64{BMPStatsTLV: tl}
			default:
				return fmt.Errorf("value length %d is not known for unknown stat type %d", tl.Length, tl.Type)
			}
		}
		if err := s.ParseValue(data); err != nil {
			return err
		}
		body.Stats = append(body.Stats, s)
		data = data[tl.Length:]
	}
	return nil
}

func (body *BMPStatisticsReport) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	body.Count = uint32(len(body.Stats))
	binary.BigEndian.PutUint32(buf[0:4], body.Count)
	for _, tlv := range body.Stats {
		tlvBuf, err := tlv.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, tlvBuf...)
	}
	return buf, nil
}

const (
	BMP_peerDownByUnknownReason = iota
	BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION
	BMP_PEER_DOWN_REASON_LOCAL_NO_NOTIFICATION
	BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION
	BMP_PEER_DOWN_REASON_REMOTE_NO_NOTIFICATION
	BMP_PEER_DOWN_REASON_PEER_DE_CONFIGURED
)

type BMPPeerDownNotification struct {
	Reason          uint8
	BGPNotification *bgp.BGPMessage
	Data            []byte
}

func NewBMPPeerDownNotification(p BMPPeerHeader, reason uint8, notification *bgp.BGPMessage, data []byte) *BMPMessage {
	b := &BMPPeerDownNotification{
		Reason: reason,
	}
	switch reason {
	case BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION, BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION:
		b.BGPNotification = notification
	case BMP_PEER_DOWN_REASON_LOCAL_NO_NOTIFICATION:
		b.Data = data
	default:
	}
	return &BMPMessage{
		Header: BMPHeader{
			Version: BMP_VERSION,
			Type:    BMP_MSG_PEER_DOWN_NOTIFICATION,
		},
		PeerHeader: p,
		Body:       b,
	}
}

func (body *BMPPeerDownNotification) ParseBody(msg *BMPMessage, data []byte) error {
	body.Reason = data[0]
	data = data[1:]
	if body.Reason == BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION || body.Reason == BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION {
		notification, err := bgp.ParseBGPMessage(data)
		if err != nil {
			return err
		}
		body.BGPNotification = notification
	} else {
		body.Data = data
	}
	return nil
}

func (body *BMPPeerDownNotification) Serialize() ([]byte, error) {
	buf := make([]byte, 1)
	buf[0] = body.Reason
	switch body.Reason {
	case BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION, BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION:
		if body.BGPNotification != nil {
			b, err := body.BGPNotification.Serialize()
			if err != nil {
				return nil, err
			} else {
				buf = append(buf, b...)
			}
		}
	default:
		if body.Data != nil {
			buf = append(buf, body.Data...)
		}
	}
	return buf, nil
}

type BMPPeerUpNotification struct {
	LocalAddress    net.IP
	LocalPort       uint16
	RemotePort      uint16
	SentOpenMsg     *bgp.BGPMessage
	ReceivedOpenMsg *bgp.BGPMessage
}

func NewBMPPeerUpNotification(p BMPPeerHeader, lAddr string, lPort, rPort uint16, sent, recv *bgp.BGPMessage) *BMPMessage {
	b := &BMPPeerUpNotification{
		LocalPort:       lPort,
		RemotePort:      rPort,
		SentOpenMsg:     sent,
		ReceivedOpenMsg: recv,
	}
	addr := net.ParseIP(lAddr)
	if addr.To4() != nil {
		b.LocalAddress = addr.To4()
	} else {
		b.LocalAddress = addr.To16()
	}
	return &BMPMessage{
		Header: BMPHeader{
			Version: BMP_VERSION,
			Type:    BMP_MSG_PEER_UP_NOTIFICATION,
		},
		PeerHeader: p,
		Body:       b,
	}
}

func (body *BMPPeerUpNotification) ParseBody(msg *BMPMessage, data []byte) error {
	if msg.PeerHeader.Flags&BMP_PEER_FLAG_IPV6 != 0 {
		body.LocalAddress = makeIP(data[:16]).To16()
	} else {
		body.LocalAddress = makeIP(data[12:16]).To4()
	}

	body.LocalPort = binary.BigEndian.Uint16(data[16:18])
	body.RemotePort = binary.BigEndian.Uint16(data[18:20])

	data = data[20:]
	sentopen, err := bgp.ParseBGPMessage(data)
	if err != nil {
		return err
	}
	body.SentOpenMsg = sentopen
	data = data[body.SentOpenMsg.Header.Len:]
	body.ReceivedOpenMsg, err = bgp.ParseBGPMessage(data)
	if err != nil {
		return err
	}
	return nil
}

func (body *BMPPeerUpNotification) Serialize() ([]byte, error) {
	buf := make([]byte, 20)
	if body.LocalAddress.To4() != nil {
		copy(buf[12:16], body.LocalAddress.To4())
	} else {
		copy(buf[:16], body.LocalAddress.To16())
	}

	binary.BigEndian.PutUint16(buf[16:18], body.LocalPort)
	binary.BigEndian.PutUint16(buf[18:20], body.RemotePort)

	m, _ := body.SentOpenMsg.Serialize()
	buf = append(buf, m...)
	m, _ = body.ReceivedOpenMsg.Serialize()
	buf = append(buf, m...)
	return buf, nil
}

const (
	BMP_INIT_TLV_TYPE_STRING = iota
	BMP_INIT_TLV_TYPE_SYS_DESCR
	BMP_INIT_TLV_TYPE_SYS_NAME
)

type BMPInfoTLVInterface interface {
	ParseValue([]byte) error
	Serialize() ([]byte, error)
}

type BMPInfoTLV struct {
	Type   uint16
	Length uint16
}

type BMPInfoTLVString struct {
	BMPInfoTLV
	Value string
}

func NewBMPInfoTLVString(t uint16, v string) *BMPInfoTLVString {
	return &BMPInfoTLVString{
		BMPInfoTLV: BMPInfoTLV{Type: t},
		Value:      v,
	}
}

func (s *BMPInfoTLVString) ParseValue(data []byte) error {
	s.Value = string(data[:s.Length])
	return nil
}

func (s *BMPInfoTLVString) Serialize() ([]byte, error) {
	s.Length = uint16(len([]byte(s.Value)))
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[0:2], s.Type)
	binary.BigEndian.PutUint16(buf[2:4], s.Length)
	buf = append(buf, []byte(s.Value)...)
	return buf, nil
}

type BMPInfoTLVUnknown struct {
	BMPInfoTLV
	Value []byte
}

func NewBMPInfoTLVUnknown(t uint16, v []byte) *BMPInfoTLVUnknown {
	return &BMPInfoTLVUnknown{
		BMPInfoTLV: BMPInfoTLV{Type: t},
		Value:      v,
	}
}

func (s *BMPInfoTLVUnknown) ParseValue(data []byte) error {
	s.Value = data[:s.Length]
	return nil
}

func (s *BMPInfoTLVUnknown) Serialize() ([]byte, error) {
	s.Length = uint16(len([]byte(s.Value)))
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[0:2], s.Type)
	binary.BigEndian.PutUint16(buf[2:4], s.Length)
	buf = append(buf, s.Value...)
	return buf, nil
}

type BMPInitiation struct {
	Info []BMPInfoTLVInterface
}

func NewBMPInitiation(info []BMPInfoTLVInterface) *BMPMessage {
	return &BMPMessage{
		Header: BMPHeader{
			Version: BMP_VERSION,
			Type:    BMP_MSG_INITIATION,
		},
		Body: &BMPInitiation{
			Info: info,
		},
	}
}

func (body *BMPInitiation) ParseBody(msg *BMPMessage, data []byte) error {
	for len(data) >= 4 {
		tl := BMPInfoTLV{
			Type:   binary.BigEndian.Uint16(data[0:2]),
			Length: binary.BigEndian.Uint16(data[2:4]),
		}
		data = data[4:]
		if len(data) < int(tl.Length) {
			return fmt.Errorf("value length is not enough: %d bytes (%d bytes expected)", len(data), tl.Length)
		}
		var tlv BMPInfoTLVInterface
		switch tl.Type {
		case BMP_INIT_TLV_TYPE_STRING, BMP_INIT_TLV_TYPE_SYS_DESCR, BMP_INIT_TLV_TYPE_SYS_NAME:
			tlv = &BMPInfoTLVString{BMPInfoTLV: tl}
		default:
			tlv = &BMPInfoTLVUnknown{BMPInfoTLV: tl}
		}
		if err := tlv.ParseValue(data); err != nil {
			return err
		}
		body.Info = append(body.Info, tlv)
		data = data[tl.Length:]
	}
	return nil
}

func (body *BMPInitiation) Serialize() ([]byte, error) {
	buf := make([]byte, 0)
	for _, tlv := range body.Info {
		b, err := tlv.Serialize()
		if err != nil {
			return buf, err
		}
		buf = append(buf, b...)
	}
	return buf, nil
}

const (
	BMP_TERM_TLV_TYPE_STRING = iota
	BMP_TERM_TLV_TYPE_REASON
)

const (
	BMP_TERM_REASON_ADMIN = iota
	BMP_TERM_REASON_UNSPEC
	BMP_TERM_REASON_OUT_OF_RESOURCES
	BMP_TERM_REASON_REDUNDANT_CONNECTION
	BMP_TERM_REASON_PERMANENTLY_ADMIN
)

type BMPTermTLVInterface interface {
	ParseValue([]byte) error
	Serialize() ([]byte, error)
}

type BMPTermTLV struct {
	Type   uint16
	Length uint16
}

type BMPTermTLVString struct {
	BMPTermTLV
	Value string
}

func NewBMPTermTLVString(t uint16, v string) *BMPTermTLVString {
	return &BMPTermTLVString{
		BMPTermTLV: BMPTermTLV{Type: t},
		Value:      v,
	}
}

func (s *BMPTermTLVString) ParseValue(data []byte) error {
	s.Value = string(data[:s.Length])
	return nil
}

func (s *BMPTermTLVString) Serialize() ([]byte, error) {
	s.Length = uint16(len([]byte(s.Value)))
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[0:2], s.Type)
	binary.BigEndian.PutUint16(buf[2:4], s.Length)
	buf = append(buf, []byte(s.Value)...)
	return buf, nil
}

type BMPTermTLV16 struct {
	BMPTermTLV
	Value uint16
}

func NewBMPTermTLV16(t uint16, v uint16) *BMPTermTLV16 {
	return &BMPTermTLV16{
		BMPTermTLV: BMPTermTLV{Type: t},
		Value:      v,
	}
}

func (s *BMPTermTLV16) ParseValue(data []byte) error {
	s.Value = binary.BigEndian.Uint16(data[:2])
	return nil
}

func (s *BMPTermTLV16) Serialize() ([]byte, error) {
	s.Length = 2
	buf := make([]byte, 6)
	binary.BigEndian.PutUint16(buf[0:2], s.Type)
	binary.BigEndian.PutUint16(buf[2:4], s.Length)
	binary.BigEndian.PutUint16(buf[4:6], s.Value)
	return buf, nil
}

type BMPTermTLVUnknown struct {
	BMPTermTLV
	Value []byte
}

func NewBMPTermTLVUnknown(t uint16, v []byte) *BMPTermTLVUnknown {
	return &BMPTermTLVUnknown{
		BMPTermTLV: BMPTermTLV{Type: t},
		Value:      v,
	}
}

func (s *BMPTermTLVUnknown) ParseValue(data []byte) error {
	s.Value = data[:s.Length]
	return nil
}

func (s *BMPTermTLVUnknown) Serialize() ([]byte, error) {
	s.Length = uint16(len([]byte(s.Value)))
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[0:2], s.Type)
	binary.BigEndian.PutUint16(buf[2:4], s.Length)
	buf = append(buf, s.Value...)
	return buf, nil
}

type BMPTermination struct {
	Info []BMPTermTLVInterface
}

func NewBMPTermination(info []BMPTermTLVInterface) *BMPMessage {
	return &BMPMessage{
		Header: BMPHeader{
			Version: BMP_VERSION,
			Type:    BMP_MSG_TERMINATION,
		},
		Body: &BMPTermination{
			Info: info,
		},
	}
}

func (body *BMPTermination) ParseBody(msg *BMPMessage, data []byte) error {
	for len(data) >= 4 {
		tl := BMPTermTLV{
			Type:   binary.BigEndian.Uint16(data[0:2]),
			Length: binary.BigEndian.Uint16(data[2:4]),
		}
		data = data[4:]
		if len(data) < int(tl.Length) {
			return fmt.Errorf("value length is not enough: %d bytes (%d bytes expected)", len(data), tl.Length)
		}
		var tlv BMPTermTLVInterface
		switch tl.Type {
		case BMP_TERM_TLV_TYPE_STRING:
			tlv = &BMPTermTLVString{BMPTermTLV: tl}
		case BMP_TERM_TLV_TYPE_REASON:
			tlv = &BMPTermTLV16{BMPTermTLV: tl}
		default:
			tlv = &BMPTermTLVUnknown{BMPTermTLV: tl}
		}
		if err := tlv.ParseValue(data); err != nil {
			return err
		}
		body.Info = append(body.Info, tlv)
		data = data[tl.Length:]
	}
	return nil
}

func (body *BMPTermination) Serialize() ([]byte, error) {
	buf := make([]byte, 0)
	for _, tlv := range body.Info {
		b, err := tlv.Serialize()
		if err != nil {
			return buf, err
		}
		buf = append(buf, b...)
	}
	return buf, nil
}

const (
	BMP_ROUTE_MIRRORING_TLV_TYPE_BGP_MSG = iota
	BMP_ROUTE_MIRRORING_TLV_TYPE_INFO
)

const (
	BMP_ROUTE_MIRRORING_INFO_ERR_PDU = iota
	BMP_ROUTE_MIRRORING_INFO_MSG_LOST
)

type BMPRouteMirrTLVInterface interface {
	ParseValue([]byte) error
	Serialize() ([]byte, error)
}

type BMPRouteMirrTLV struct {
	Type   uint16
	Length uint16
}

type BMPRouteMirrTLVBGPMsg struct {
	BMPRouteMirrTLV
	Value *bgp.BGPMessage
}

func NewBMPRouteMirrTLVBGPMsg(t uint16, v *bgp.BGPMessage) *BMPRouteMirrTLVBGPMsg {
	return &BMPRouteMirrTLVBGPMsg{
		BMPRouteMirrTLV: BMPRouteMirrTLV{Type: t},
		Value:           v,
	}
}

func (s *BMPRouteMirrTLVBGPMsg) ParseValue(data []byte) error {
	v, err := bgp.ParseBGPMessage(data)
	if err != nil {
		return err
	}
	s.Value = v
	return nil
}

func (s *BMPRouteMirrTLVBGPMsg) Serialize() ([]byte, error) {
	m, err := s.Value.Serialize()
	if err != nil {
		return nil, err
	}
	s.Length = uint16(len(m))
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[0:2], s.Type)
	binary.BigEndian.PutUint16(buf[2:4], s.Length)
	buf = append(buf, m...)
	return buf, nil
}

type BMPRouteMirrTLV16 struct {
	BMPRouteMirrTLV
	Value uint16
}

func NewBMPRouteMirrTLV16(t uint16, v uint16) *BMPRouteMirrTLV16 {
	return &BMPRouteMirrTLV16{
		BMPRouteMirrTLV: BMPRouteMirrTLV{Type: t},
		Value:           v,
	}
}

func (s *BMPRouteMirrTLV16) ParseValue(data []byte) error {
	s.Value = binary.BigEndian.Uint16(data[:2])
	return nil
}

func (s *BMPRouteMirrTLV16) Serialize() ([]byte, error) {
	s.Length = 2
	buf := make([]byte, 6)
	binary.BigEndian.PutUint16(buf[0:2], s.Type)
	binary.BigEndian.PutUint16(buf[2:4], s.Length)
	binary.BigEndian.PutUint16(buf[4:6], s.Value)
	return buf, nil
}

type BMPRouteMirrTLVUnknown struct {
	BMPRouteMirrTLV
	Value []byte
}

func NewBMPRouteMirrTLVUnknown(t uint16, v []byte) *BMPRouteMirrTLVUnknown {
	return &BMPRouteMirrTLVUnknown{
		BMPRouteMirrTLV: BMPRouteMirrTLV{Type: t},
		Value:           v,
	}
}

func (s *BMPRouteMirrTLVUnknown) ParseValue(data []byte) error {
	s.Value = data[:s.Length]
	return nil
}

func (s *BMPRouteMirrTLVUnknown) Serialize() ([]byte, error) {
	s.Length = uint16(len([]byte(s.Value)))
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[0:2], s.Type)
	binary.BigEndian.PutUint16(buf[2:4], s.Length)
	buf = append(buf, s.Value...)
	return buf, nil
}

type BMPRouteMirroring struct {
	Info []BMPRouteMirrTLVInterface
}

func NewBMPRouteMirroring(p BMPPeerHeader, info []BMPRouteMirrTLVInterface) *BMPMessage {
	return &BMPMessage{
		Header: BMPHeader{
			Version: BMP_VERSION,
			Type:    BMP_MSG_ROUTE_MIRRORING,
		},
		PeerHeader: p,
		Body: &BMPRouteMirroring{
			Info: info,
		},
	}
}

func (body *BMPRouteMirroring) ParseBody(msg *BMPMessage, data []byte) error {
	for len(data) >= 4 {
		tl := BMPRouteMirrTLV{
			Type:   binary.BigEndian.Uint16(data[0:2]),
			Length: binary.BigEndian.Uint16(data[2:4]),
		}
		data = data[4:]
		if len(data) < int(tl.Length) {
			return fmt.Errorf("value length is not enough: %d bytes (%d bytes expected)", len(data), tl.Length)
		}
		var tlv BMPRouteMirrTLVInterface
		switch tl.Type {
		case BMP_ROUTE_MIRRORING_TLV_TYPE_BGP_MSG:
			tlv = &BMPRouteMirrTLVBGPMsg{BMPRouteMirrTLV: tl}
		case BMP_ROUTE_MIRRORING_TLV_TYPE_INFO:
			tlv = &BMPRouteMirrTLV16{BMPRouteMirrTLV: tl}
		default:
			tlv = &BMPRouteMirrTLVUnknown{BMPRouteMirrTLV: tl}
		}
		if err := tlv.ParseValue(data); err != nil {
			return err
		}
		body.Info = append(body.Info, tlv)
		data = data[tl.Length:]
	}
	return nil
}

func (body *BMPRouteMirroring) Serialize() ([]byte, error) {
	buf := make([]byte, 0)
	for _, tlv := range body.Info {
		b, err := tlv.Serialize()
		if err != nil {
			return buf, err
		}
		buf = append(buf, b...)
	}
	return buf, nil
}

type BMPBody interface {
	// Sigh, some body messages need a BMPHeader to parse the body
	// data so we need to pass BMPHeader (avoid DecodeFromBytes
	// function name).
	ParseBody(*BMPMessage, []byte) error
	Serialize() ([]byte, error)
}

type BMPMessage struct {
	Header     BMPHeader
	PeerHeader BMPPeerHeader
	Body       BMPBody
}

func (msg *BMPMessage) Serialize() ([]byte, error) {
	buf := make([]byte, 0)
	if msg.Header.Type != BMP_MSG_INITIATION && msg.Header.Type != BMP_MSG_TERMINATION {
		p, err := msg.PeerHeader.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, p...)
	}

	b, err := msg.Body.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, b...)

	if msg.Header.Length == 0 {
		msg.Header.Length = uint32(BMP_HEADER_SIZE + len(buf))
	}

	h, err := msg.Header.Serialize()
	if err != nil {
		return nil, err
	}
	return append(h, buf...), nil
}

func (msg *BMPMessage) Len() int {
	return int(msg.Header.Length)
}

const (
	BMP_MSG_ROUTE_MONITORING = iota
	BMP_MSG_STATISTICS_REPORT
	BMP_MSG_PEER_DOWN_NOTIFICATION
	BMP_MSG_PEER_UP_NOTIFICATION
	BMP_MSG_INITIATION
	BMP_MSG_TERMINATION
	BMP_MSG_ROUTE_MIRRORING
)

func ParseBMPMessage(data []byte) (msg *BMPMessage, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("not all data bytes are available")
		}
	}()

	msg = &BMPMessage{}
	err = msg.Header.DecodeFromBytes(data)
	if err != nil {
		return nil, err
	}
	data = data[BMP_HEADER_SIZE:msg.Header.Length]

	switch msg.Header.Type {
	case BMP_MSG_ROUTE_MONITORING:
		msg.Body = &BMPRouteMonitoring{}
	case BMP_MSG_STATISTICS_REPORT:
		msg.Body = &BMPStatisticsReport{}
	case BMP_MSG_PEER_DOWN_NOTIFICATION:
		msg.Body = &BMPPeerDownNotification{}
	case BMP_MSG_PEER_UP_NOTIFICATION:
		msg.Body = &BMPPeerUpNotification{}
	case BMP_MSG_INITIATION:
		msg.Body = &BMPInitiation{}
	case BMP_MSG_TERMINATION:
		msg.Body = &BMPTermination{}
	case BMP_MSG_ROUTE_MIRRORING:
		msg.Body = &BMPRouteMirroring{}
	default:
		return nil, fmt.Errorf("unsupported BMP message type: %d", msg.Header.Type)
	}

	if msg.Header.Type != BMP_MSG_INITIATION && msg.Header.Type != BMP_MSG_TERMINATION {
		msg.PeerHeader.DecodeFromBytes(data)
		data = data[BMP_PEER_HEADER_SIZE:]
	}

	err = msg.Body.ParseBody(msg, data)
	if err != nil {
		if msg.Header.Type == BMP_MSG_ROUTE_MONITORING {
			return msg, err
		}

		return nil, err
	}

	return msg, nil
}

func SplitBMP(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 || len(data) < BMP_HEADER_SIZE {
		return 0, nil, nil
	}
	tmpHdr := &BMPHeader{}
	if err = tmpHdr.DecodeFromBytes(data[:BMP_HEADER_SIZE]); err != nil {
		return 0, nil, nil
	}
	if len(data) < int(tmpHdr.Length) {
		return 0, nil, nil
	}
	return int(tmpHdr.Length), data[0:tmpHdr.Length], nil
}
