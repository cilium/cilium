// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
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

package mrt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

const (
	MRT_COMMON_HEADER_LEN = 12
)

type MRTType uint16

const (
	NULL         MRTType = 0  // deprecated
	START        MRTType = 1  // deprecated
	DIE          MRTType = 2  // deprecated
	I_AM_DEAD    MRTType = 3  // deprecated
	PEER_DOWN    MRTType = 4  // deprecated
	BGP          MRTType = 5  // deprecated
	RIP          MRTType = 6  // deprecated
	IDRP         MRTType = 7  // deprecated
	RIPNG        MRTType = 8  // deprecated
	BGP4PLUS     MRTType = 9  // deprecated
	BGP4PLUS01   MRTType = 10 // deprecated
	OSPFv2       MRTType = 11
	TABLE_DUMP   MRTType = 12
	TABLE_DUMPv2 MRTType = 13
	BGP4MP       MRTType = 16
	BGP4MP_ET    MRTType = 17
	ISIS         MRTType = 32
	ISIS_ET      MRTType = 33
	OSPFv3       MRTType = 48
	OSPFv3_ET    MRTType = 49
)

func (t MRTType) HasExtendedTimestamp() bool {
	switch t {
	case BGP4MP_ET, ISIS_ET, OSPFv3_ET:
		return true
	default:
		return false
	}
}

type MRTSubTyper interface {
	ToUint16() uint16
}

type MRTSubTypeTableDumpv2 uint16

const (
	PEER_INDEX_TABLE           MRTSubTypeTableDumpv2 = 1
	RIB_IPV4_UNICAST           MRTSubTypeTableDumpv2 = 2
	RIB_IPV4_MULTICAST         MRTSubTypeTableDumpv2 = 3
	RIB_IPV6_UNICAST           MRTSubTypeTableDumpv2 = 4
	RIB_IPV6_MULTICAST         MRTSubTypeTableDumpv2 = 5
	RIB_GENERIC                MRTSubTypeTableDumpv2 = 6
	GEO_PEER_TABLE             MRTSubTypeTableDumpv2 = 7  // RFC6397
	RIB_IPV4_UNICAST_ADDPATH   MRTSubTypeTableDumpv2 = 8  // RFC8050
	RIB_IPV4_MULTICAST_ADDPATH MRTSubTypeTableDumpv2 = 9  // RFC8050
	RIB_IPV6_UNICAST_ADDPATH   MRTSubTypeTableDumpv2 = 10 // RFC8050
	RIB_IPV6_MULTICAST_ADDPATH MRTSubTypeTableDumpv2 = 11 // RFC8050
	RIB_GENERIC_ADDPATH        MRTSubTypeTableDumpv2 = 12 // RFC8050
)

func (t MRTSubTypeTableDumpv2) ToUint16() uint16 {
	return uint16(t)
}

type MRTSubTypeBGP4MP uint16

const (
	STATE_CHANGE              MRTSubTypeBGP4MP = 0
	MESSAGE                   MRTSubTypeBGP4MP = 1
	MESSAGE_AS4               MRTSubTypeBGP4MP = 4
	STATE_CHANGE_AS4          MRTSubTypeBGP4MP = 5
	MESSAGE_LOCAL             MRTSubTypeBGP4MP = 6
	MESSAGE_AS4_LOCAL         MRTSubTypeBGP4MP = 7
	MESSAGE_ADDPATH           MRTSubTypeBGP4MP = 8  // RFC8050
	MESSAGE_AS4_ADDPATH       MRTSubTypeBGP4MP = 9  // RFC8050
	MESSAGE_LOCAL_ADDPATH     MRTSubTypeBGP4MP = 10 // RFC8050
	MESSAGE_AS4_LOCAL_ADDPATH MRTSubTypeBGP4MP = 11 // RFC8050
)

func (t MRTSubTypeBGP4MP) ToUint16() uint16 {
	return uint16(t)
}

type BGPState uint16

const (
	IDLE        BGPState = 1
	CONNECT     BGPState = 2
	ACTIVE      BGPState = 3
	OPENSENT    BGPState = 4
	OPENCONFIRM BGPState = 5
	ESTABLISHED BGPState = 6
)

func packValues(values ...any) ([]byte, error) {
	b := new(bytes.Buffer)
	for _, v := range values {
		err := binary.Write(b, binary.BigEndian, v)
		if err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}

type MRTHeader struct {
	Timestamp                     uint32
	Type                          MRTType
	SubType                       uint16
	Len                           uint32
	ExtendedTimestampMicroseconds uint32
}

func ParseHeader(data []byte) (*MRTHeader, error) {
	if len(data) < MRT_COMMON_HEADER_LEN {
		return nil, fmt.Errorf("not all MRTHeader bytes are available. expected: %d, actual: %d", MRT_COMMON_HEADER_LEN, len(data))
	}
	h := &MRTHeader{}
	h.Timestamp = binary.BigEndian.Uint32(data[:4])
	h.Type = MRTType(binary.BigEndian.Uint16(data[4:6]))
	h.SubType = binary.BigEndian.Uint16(data[6:8])
	h.Len = binary.BigEndian.Uint32(data[8:12])
	if h.Type.HasExtendedTimestamp() {
		if len(data) < 16 {
			return nil, fmt.Errorf("not all MRTHeader bytes are available. expected: %d, actual: %d", 16, len(data))
		}
		h.ExtendedTimestampMicroseconds = binary.BigEndian.Uint32(data[12:16])
	}
	return h, nil
}

func (h *MRTHeader) Serialize() ([]byte, error) {
	fields := []any{h.Timestamp, h.Type, h.SubType, h.Len}
	if h.Type.HasExtendedTimestamp() {
		fields = append(fields, h.ExtendedTimestampMicroseconds)
	}
	return packValues(fields...)
}

func NewMRTHeader(timestamp time.Time, t MRTType, subtype MRTSubTyper, l uint32) (*MRTHeader, error) {
	ms := uint32(0)
	if t.HasExtendedTimestamp() {
		ms = uint32(timestamp.UnixMicro() - timestamp.Unix()*1000000)
	}
	return &MRTHeader{
		Timestamp:                     uint32(timestamp.Unix()),
		Type:                          t,
		SubType:                       subtype.ToUint16(),
		Len:                           l,
		ExtendedTimestampMicroseconds: ms,
	}, nil
}

func (h *MRTHeader) GetTime() time.Time {
	t := int64(h.Timestamp)
	ms := int64(h.ExtendedTimestampMicroseconds)
	return time.Unix(t, ms*1000)
}

type MRTMessage struct {
	Header MRTHeader
	Body   Body
}

func (m *MRTMessage) Serialize() ([]byte, error) {
	buf, err := m.Body.Serialize()
	if err != nil {
		return nil, err
	}
	m.Header.Len = uint32(len(buf))
	bbuf, err := m.Header.Serialize()
	if err != nil {
		return nil, err
	}
	return append(bbuf, buf...), nil
}

func NewMRTMessage(timestamp time.Time, t MRTType, subtype MRTSubTyper, body Body) (*MRTMessage, error) {
	header, err := NewMRTHeader(timestamp, t, subtype, 0)
	if err != nil {
		return nil, err
	}
	return &MRTMessage{
		Header: *header,
		Body:   body,
	}, nil
}

type Body interface {
	Serialize() ([]byte, error)
}

type Peer struct {
	Type      uint8
	BgpId     netip.Addr
	IpAddress netip.Addr
	AS        uint32
}

var errNotAllPeerBytesAvailable = errors.New("not all Peer bytes are available")

func (p *Peer) decodeFromBytes(data []byte) ([]byte, error) {
	if len(data) < 5 {
		return nil, errNotAllPeerBytesAvailable
	}
	p.Type = data[0]
	p.BgpId, _ = netip.AddrFromSlice(data[1:5])
	data = data[5:]

	if p.Type&1 > 0 {
		if len(data) < 16 {
			return nil, errNotAllPeerBytesAvailable
		}
		p.IpAddress, _ = netip.AddrFromSlice(data[:16])
		data = data[16:]
	} else {
		if len(data) < 4 {
			return nil, errNotAllPeerBytesAvailable
		}
		p.IpAddress, _ = netip.AddrFromSlice(data[:4])
		data = data[4:]
	}

	if p.Type&(1<<1) > 0 {
		if len(data) < 4 {
			return nil, errNotAllPeerBytesAvailable
		}
		p.AS = binary.BigEndian.Uint32(data[:4])
		data = data[4:]
	} else {
		if len(data) < 2 {
			return nil, errNotAllPeerBytesAvailable
		}
		p.AS = uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}

	return data, nil
}

func (p *Peer) Serialize() ([]byte, error) {
	var err error
	var bbuf []byte
	buf := make([]byte, 5)
	buf[0] = p.Type
	copy(buf[1:], p.BgpId.AsSlice())
	if p.Type&1 > 0 {
		buf = append(buf, p.IpAddress.AsSlice()...)
	} else {
		buf = append(buf, p.IpAddress.AsSlice()...)
	}
	if p.Type&(1<<1) > 0 {
		bbuf, err = packValues(p.AS)
	} else {
		if p.AS > uint32(math.MaxUint16) {
			return nil, fmt.Errorf("AS number is beyond 2 octet. %d > %d", p.AS, math.MaxUint16)
		}
		bbuf, err = packValues(uint16(p.AS))
	}
	if err != nil {
		return nil, err
	}
	return append(buf, bbuf...), nil
}

func NewPeer(bgpid netip.Addr, ipaddr netip.Addr, asn uint32, isAS4 bool) *Peer {
	// TODO: return error if bgpid is IPv6
	t := 0
	if ipaddr.Is6() {
		t |= 1
	}
	if isAS4 {
		t |= 1 << 1
	}
	return &Peer{
		Type:      uint8(t),
		BgpId:     bgpid,
		IpAddress: ipaddr,
		AS:        asn,
	}
}

func (p *Peer) String() string {
	return fmt.Sprintf("PEER ENTRY: ID [%s] Addr [%s] AS [%d]", p.BgpId, p.IpAddress, p.AS)
}

type PeerIndexTable struct {
	CollectorBgpId netip.Addr
	ViewName       string
	Peers          []*Peer
}

var errNnotAllPeerIndexBytesAvailable = errors.New("not all PeerIndexTable bytes are available")

func parsePeerIndexTable(data []byte) (*PeerIndexTable, error) {
	t := &PeerIndexTable{}
	if len(data) < 6 {
		return nil, errNnotAllPeerIndexBytesAvailable
	}
	t.CollectorBgpId, _ = netip.AddrFromSlice(data[:4])
	viewLen := int(binary.BigEndian.Uint16(data[4:6]))
	viewEnd := 6 + viewLen
	if len(data) < viewEnd {
		return nil, errNnotAllPeerIndexBytesAvailable
	}
	t.ViewName = string(data[6:viewEnd])

	data = data[viewEnd:]

	if len(data) < 2 {
		return nil, errNnotAllPeerIndexBytesAvailable
	}
	peerNum := binary.BigEndian.Uint16(data[:2])
	data = data[2:]
	t.Peers = make([]*Peer, 0, peerNum)
	var err error
	for range peerNum {
		p := &Peer{}
		data, err = p.decodeFromBytes(data)
		if err != nil {
			return nil, err
		}
		t.Peers = append(t.Peers, p)
	}

	return t, nil
}

func (t *PeerIndexTable) Serialize() ([]byte, error) {
	buf := make([]byte, 8+len(t.ViewName))
	copy(buf, t.CollectorBgpId.AsSlice())
	binary.BigEndian.PutUint16(buf[4:], uint16(len(t.ViewName)))
	copy(buf[6:], t.ViewName)
	binary.BigEndian.PutUint16(buf[6+len(t.ViewName):], uint16(len(t.Peers)))
	for _, peer := range t.Peers {
		bbuf, err := peer.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, bbuf...)
	}
	return buf, nil
}

func NewPeerIndexTable(bgpid netip.Addr, viewname string, peers []*Peer) *PeerIndexTable {
	// TODO: return error if bgpid is IPv6
	return &PeerIndexTable{
		CollectorBgpId: bgpid,
		ViewName:       viewname,
		Peers:          peers,
	}
}

func (t *PeerIndexTable) String() string {
	return fmt.Sprintf("PEER_INDEX_TABLE: CollectorBgpId [%s] ViewName [%s] Peers [%s]", t.CollectorBgpId, t.ViewName, t.Peers)
}

type RibEntry struct {
	PeerIndex      uint16
	OriginatedTime uint32
	PathIdentifier uint32
	PathAttributes []bgp.PathAttributeInterface
	isAddPath      bool
}

var errNotAllRibEntryBytesAvailable = errors.New("not all RibEntry bytes are available")

func parseRibEntry(data []byte, family bgp.Family, isAddPath bool, prefix ...bgp.NLRI) (*RibEntry, []byte, error) {
	if len(data) < 8 {
		return nil, data, errNotAllRibEntryBytesAvailable
	}
	e := &RibEntry{
		isAddPath: isAddPath,
	}
	e.PeerIndex = binary.BigEndian.Uint16(data[:2])
	e.OriginatedTime = binary.BigEndian.Uint32(data[2:6])
	if e.isAddPath {
		if len(data) < 10+2 {
			return nil, nil, errNotAllRibEntryBytesAvailable
		}
		e.PathIdentifier = binary.BigEndian.Uint32(data[6:10])
		data = data[10:]
	} else {
		data = data[6:]
	}
	totalLen := binary.BigEndian.Uint16(data[:2])
	data = data[2:]
	if len(data) < int(totalLen) {
		return nil, nil, errNotAllRibEntryBytesAvailable
	}
	options := &bgp.MarshallingOption{
		MRT: true,
	}
	for attrLen := totalLen; attrLen > 0; {
		p, err := bgp.GetPathAttribute(data)
		if err != nil {
			return nil, nil, err
		}

		// HACK: keeps compatibility
		if len(prefix) > 1 {
			return nil, nil, fmt.Errorf("only one prefix should be used")
		}
		err = p.DecodeFromBytes(data, options)
		if err != nil {
			return nil, nil, err
		}

		// RFC 6396 4.3.4
		mp, ok := p.(*bgp.PathAttributeMpReachNLRI)
		if ok && len(prefix) == 0 {
			return nil, nil, fmt.Errorf("prefix is not provided for MP_REACH_NLRI")
		} else if ok {
			mp.AFI = family.Afi()
			mp.SAFI = family.Safi()
			mp.Value = []bgp.PathNLRI{{NLRI: prefix[0], ID: e.PathIdentifier}}
		}

		pLen := uint16(p.Len())
		if pLen > attrLen {
			return nil, nil, fmt.Errorf("path attribute length %d exceeds remaining attribute length %d", pLen, attrLen)
		}
		attrLen -= pLen
		data = data[p.Len():]
		e.PathAttributes = append(e.PathAttributes, p)
	}
	return e, data, nil
}

func (e *RibEntry) Serialize() ([]byte, error) {
	pbuf := make([]byte, 0)
	totalLen := 0
	options := &bgp.MarshallingOption{
		MRT: true,
	}
	for _, pattr := range e.PathAttributes {
		pb, err := pattr.Serialize(options)
		if err != nil {
			return nil, err
		}
		pbuf = append(pbuf, pb...)
		totalLen += len(pb)
	}
	var buf []byte
	if e.isAddPath {
		buf = make([]byte, 12, 12+len(pbuf))
		binary.BigEndian.PutUint16(buf, e.PeerIndex)
		binary.BigEndian.PutUint32(buf[2:], e.OriginatedTime)
		binary.BigEndian.PutUint32(buf[6:], e.PathIdentifier)
		binary.BigEndian.PutUint16(buf[10:], uint16(totalLen))
	} else {
		buf = make([]byte, 8, 8+len(pbuf))
		binary.BigEndian.PutUint16(buf, e.PeerIndex)
		binary.BigEndian.PutUint32(buf[2:], e.OriginatedTime)
		binary.BigEndian.PutUint16(buf[6:], uint16(totalLen))
	}
	buf = append(buf, pbuf...)
	return buf, nil
}

func NewRibEntry(index uint16, time uint32, pathId uint32, pathAttrs []bgp.PathAttributeInterface, isAddPath bool) *RibEntry {
	return &RibEntry{
		PeerIndex:      index,
		OriginatedTime: time,
		PathIdentifier: pathId,
		PathAttributes: pathAttrs,
		isAddPath:      isAddPath,
	}
}

func (e *RibEntry) String() string {
	if e.isAddPath {
		return fmt.Sprintf("RIB_ENTRY: PeerIndex [%d] OriginatedTime [%d] PathIdentifier[%d] PathAttributes [%v]", e.PeerIndex, e.OriginatedTime, e.PathIdentifier, e.PathAttributes)
	} else {
		return fmt.Sprintf("RIB_ENTRY: PeerIndex [%d] OriginatedTime [%d] PathAttributes [%v]", e.PeerIndex, e.OriginatedTime, e.PathAttributes)
	}
}

type Rib struct {
	SequenceNumber uint32
	Prefix         bgp.NLRI
	Entries        []*RibEntry
	Family         bgp.Family
	isAddPath      bool
}

func parseRib(data []byte, family bgp.Family, isAddPath bool) (*Rib, error) {
	u := &Rib{
		Family:    family,
		isAddPath: isAddPath,
	}
	if len(data) < 4 {
		return nil, errors.New("not all RibIpv4Unicast message bytes available")
	}
	u.SequenceNumber = binary.BigEndian.Uint32(data[:4])
	data = data[4:]
	afi, safi := u.Family.Afi(), u.Family.Safi()
	if afi == 0 && safi == 0 {
		if len(data) < 3 {
			return nil, errors.New("not all RibIpv4Unicast message bytes available")
		}
		afi = binary.BigEndian.Uint16(data[:2])
		safi = data[2]
		data = data[3:]
		family = bgp.NewFamily(afi, safi)
	}
	prefix, err := bgp.NLRIFromSlice(family, data)
	if err != nil {
		return nil, err
	}
	u.Prefix = prefix
	if len(data) < prefix.Len()+2 {
		return nil, errors.New("not all RibIpv4Unicast message bytes available")
	}
	data = data[prefix.Len():]
	entryNum := binary.BigEndian.Uint16(data[:2])
	data = data[2:]
	u.Entries = make([]*RibEntry, 0, entryNum)
	for range entryNum {
		var e *RibEntry
		e, data, err = parseRibEntry(data, family, u.isAddPath, prefix)
		if err != nil {
			return nil, err
		}
		u.Entries = append(u.Entries, e)
	}
	return u, nil
}

func (u *Rib) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, u.SequenceNumber)
	switch u.Family {
	case bgp.RF_FS_IPv4_UC, bgp.RF_IPv4_MC, bgp.RF_IPv6_UC, bgp.RF_IPv6_MC:
		var bbuf [2]byte
		binary.BigEndian.PutUint16(bbuf[:], u.Family.Afi())
		buf = append(buf, bbuf[:]...)
		buf = append(buf, u.Family.Safi())
	default:
	}
	bbuf, err := u.Prefix.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, bbuf...)
	bbuf, err = packValues(uint16(len(u.Entries)))
	if err != nil {
		return nil, err
	}
	buf = append(buf, bbuf...)
	for _, entry := range u.Entries {
		bbuf, err = entry.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, bbuf...)
	}
	return buf, nil
}

func NewRib(seq uint32, family bgp.Family, prefix bgp.NLRI, entries []*RibEntry) *Rib {
	return &Rib{
		SequenceNumber: seq,
		Family:         family,
		Prefix:         prefix,
		Entries:        entries,
		isAddPath:      entries[0].isAddPath,
	}
}

func (u *Rib) String() string {
	return fmt.Sprintf("RIB: Seq [%d] Prefix [%s] Entries [%s]", u.SequenceNumber, u.Prefix, u.Entries)
}

type GeoPeer struct {
	Type      uint8
	BgpId     netip.Addr
	Latitude  float32
	Longitude float32
}

func (p *GeoPeer) decodeFromBytes(data []byte) ([]byte, error) {
	if len(data) < 13 {
		return nil, fmt.Errorf("not all GeoPeer bytes are available")
	}
	// Peer IP Address and Peer AS should not be included
	p.Type = data[0]
	if p.Type != uint8(0) {
		return nil, fmt.Errorf("unsupported peer type for GeoPeer: %d", p.Type)
	}
	p.BgpId, _ = netip.AddrFromSlice(data[1:5])
	p.Latitude = math.Float32frombits(binary.BigEndian.Uint32(data[5:9]))
	p.Longitude = math.Float32frombits(binary.BigEndian.Uint32(data[9:13]))
	return data[13:], nil
}

func (p *GeoPeer) Serialize() ([]byte, error) {
	buf := make([]byte, 13)
	buf[0] = uint8(0) // Peer IP Address and Peer AS should not be included
	if !p.BgpId.Is4() {
		return nil, fmt.Errorf("invalid BgpId: %s", p.BgpId)
	}
	copy(buf[1:5], p.BgpId.AsSlice())
	binary.BigEndian.PutUint32(buf[5:9], math.Float32bits(p.Latitude))
	binary.BigEndian.PutUint32(buf[9:13], math.Float32bits(p.Longitude))
	return buf, nil
}

func NewGeoPeer(bgpid netip.Addr, latitude float32, longitude float32) (*GeoPeer, error) {
	if !bgpid.Is4() {
		return nil, fmt.Errorf("invalid BgpId: %s", bgpid)
	}

	return &GeoPeer{
		Type:      0, // Peer IP Address and Peer AS should not be included
		BgpId:     bgpid,
		Latitude:  latitude,
		Longitude: longitude,
	}, nil
}

func (p *GeoPeer) String() string {
	return fmt.Sprintf("PEER ENTRY: ID [%s] Latitude [%f] Longitude [%f]", p.BgpId, p.Latitude, p.Longitude)
}

type GeoPeerTable struct {
	CollectorBgpId     netip.Addr
	CollectorLatitude  float32
	CollectorLongitude float32
	Peers              []*GeoPeer
}

func parseGeoPeerTable(data []byte) (*GeoPeerTable, error) {
	if len(data) < 14 {
		return nil, fmt.Errorf("not all GeoPeerTable bytes are available")
	}
	t := &GeoPeerTable{}
	t.CollectorBgpId, _ = netip.AddrFromSlice(data[:4])
	t.CollectorLatitude = math.Float32frombits(binary.BigEndian.Uint32(data[4:8]))
	t.CollectorLongitude = math.Float32frombits(binary.BigEndian.Uint32(data[8:12]))
	peerCount := binary.BigEndian.Uint16(data[12:14])
	data = data[14:]
	t.Peers = make([]*GeoPeer, 0, peerCount)
	var err error
	for range peerCount {
		p := &GeoPeer{}
		if data, err = p.decodeFromBytes(data); err != nil {
			return nil, err
		}
		t.Peers = append(t.Peers, p)
	}
	return t, nil
}

func (t *GeoPeerTable) Serialize() ([]byte, error) {
	buf := make([]byte, 14)
	if !t.CollectorBgpId.Is4() {
		return nil, fmt.Errorf("invalid CollectorBgpId: %s", t.CollectorBgpId)
	}
	copy(buf[:4], t.CollectorBgpId.AsSlice())
	binary.BigEndian.PutUint32(buf[4:8], math.Float32bits(t.CollectorLatitude))
	binary.BigEndian.PutUint32(buf[8:12], math.Float32bits(t.CollectorLongitude))
	binary.BigEndian.PutUint16(buf[12:14], uint16(len(t.Peers)))
	for _, peer := range t.Peers {
		pbuf, err := peer.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, pbuf...)
	}
	return buf, nil
}

func NewGeoPeerTable(bgpid netip.Addr, latitude float32, longitude float32, peers []*GeoPeer) (*GeoPeerTable, error) {
	if !bgpid.Is4() {
		return nil, fmt.Errorf("invalid BgpId: %s", bgpid)
	}
	return &GeoPeerTable{
		CollectorBgpId:     bgpid,
		CollectorLatitude:  latitude,
		CollectorLongitude: longitude,
		Peers:              peers,
	}, nil
}

func (t *GeoPeerTable) String() string {
	return fmt.Sprintf("GEO_PEER_TABLE: CollectorBgpId [%s] CollectorLatitude [%f] CollectorLongitude [%f] Peers [%s]", t.CollectorBgpId, t.CollectorLatitude, t.CollectorLongitude, t.Peers)
}

type BGP4MPHeader struct {
	PeerAS         uint32
	LocalAS        uint32
	InterfaceIndex uint16
	AddressFamily  uint16
	PeerIpAddress  netip.Addr
	LocalIpAddress netip.Addr
	isAS4          bool
}

func (m *BGP4MPHeader) decodeFromBytes(data []byte) ([]byte, error) {
	if m.isAS4 && len(data) < 12 {
		return nil, errors.New("not all BGP4MPMessageAS4 bytes available")
	} else if !m.isAS4 && len(data) < 8 {
		return nil, errors.New("not all BGP4MPMessageAS bytes available")
	}

	if m.isAS4 {
		m.PeerAS = binary.BigEndian.Uint32(data[:4])
		m.LocalAS = binary.BigEndian.Uint32(data[4:8])
		data = data[8:]
	} else {
		m.PeerAS = uint32(binary.BigEndian.Uint16(data[:2]))
		m.LocalAS = uint32(binary.BigEndian.Uint16(data[2:4]))
		data = data[4:]
	}
	m.InterfaceIndex = binary.BigEndian.Uint16(data[:2])
	m.AddressFamily = binary.BigEndian.Uint16(data[2:4])
	switch m.AddressFamily {
	case bgp.AFI_IP:
		if len(data) < 12 {
			return nil, errors.New("not all IPv4 peer bytes available")
		}
		m.PeerIpAddress, _ = netip.AddrFromSlice(data[4:8])
		m.LocalIpAddress, _ = netip.AddrFromSlice(data[8:12])
		data = data[12:]
	case bgp.AFI_IP6:
		if len(data) < 36 {
			return nil, errors.New("not all IPv6 peer bytes available")
		}
		m.PeerIpAddress, _ = netip.AddrFromSlice(data[4:20])
		m.LocalIpAddress, _ = netip.AddrFromSlice(data[20:36])
		data = data[36:]
	default:
		return nil, fmt.Errorf("unsupported address family: %d", m.AddressFamily)
	}
	return data, nil
}

func (m *BGP4MPHeader) serialize() ([]byte, error) {
	var values []any
	if m.isAS4 {
		values = []any{m.PeerAS, m.LocalAS, m.InterfaceIndex, m.AddressFamily}
	} else {
		values = []any{uint16(m.PeerAS), uint16(m.LocalAS), m.InterfaceIndex, m.AddressFamily}
	}
	buf, err := packValues(values...)
	if err != nil {
		return nil, err
	}
	var bbuf []byte
	switch m.AddressFamily {
	case bgp.AFI_IP:
		bbuf = make([]byte, 8)
		copy(bbuf, m.PeerIpAddress.AsSlice())
		copy(bbuf[4:], m.LocalIpAddress.AsSlice())
	case bgp.AFI_IP6:
		bbuf = make([]byte, 32)
		copy(bbuf, m.PeerIpAddress.AsSlice())
		copy(bbuf[16:], m.LocalIpAddress.AsSlice())
	default:
		return nil, fmt.Errorf("unsupported address family: %d", m.AddressFamily)
	}
	return append(buf, bbuf...), nil
}

func newBGP4MPHeader(peeras, localas uint32, intfindex uint16, peerip, localip netip.Addr, isAS4 bool) (*BGP4MPHeader, error) {
	var af uint16

	if !peerip.IsValid() || !localip.IsValid() {
		return nil, fmt.Errorf("Peer IP Address and Local IP Address must be valid")
	}

	if peerip.Is4() && localip.Is4() {
		af = bgp.AFI_IP
	} else if peerip.Is6() && localip.Is6() {
		af = bgp.AFI_IP6
	} else {
		return nil, fmt.Errorf("peer IP Address and Local IP Address must have the same address family")
	}

	return &BGP4MPHeader{
		PeerAS:         peeras,
		LocalAS:        localas,
		InterfaceIndex: intfindex,
		AddressFamily:  af,
		PeerIpAddress:  peerip,
		LocalIpAddress: localip,
		isAS4:          isAS4,
	}, nil
}

type BGP4MPStateChange struct {
	*BGP4MPHeader
	OldState BGPState
	NewState BGPState
}

func parseBGP4MPStateChange(hdr *BGP4MPHeader, data []byte) (*BGP4MPStateChange, error) {
	m := &BGP4MPStateChange{
		BGP4MPHeader: hdr,
	}
	rest, err := m.decodeFromBytes(data)
	if err != nil {
		return nil, err
	}
	if len(rest) < 4 {
		return nil, fmt.Errorf("not all BGP4MPStateChange bytes available")
	}
	m.OldState = BGPState(binary.BigEndian.Uint16(rest[:2]))
	m.NewState = BGPState(binary.BigEndian.Uint16(rest[2:4]))
	return m, nil
}

func (m *BGP4MPStateChange) Serialize() ([]byte, error) {
	buf, err := m.serialize()
	if err != nil {
		return nil, err
	}
	bbuf, err := packValues(m.OldState, m.NewState)
	if err != nil {
		return nil, err
	}
	return append(buf, bbuf...), nil
}

func NewBGP4MPStateChange(peeras, localas uint32, intfindex uint16, peerip, localip netip.Addr, isAS4 bool, oldstate, newstate BGPState) (*BGP4MPStateChange, error) {
	header, err := newBGP4MPHeader(peeras, localas, intfindex, peerip, localip, isAS4)
	if err != nil {
		return nil, err
	}

	return &BGP4MPStateChange{
		BGP4MPHeader: header,
		OldState:     oldstate,
		NewState:     newstate,
	}, nil
}

type BGP4MPMessage struct {
	*BGP4MPHeader
	BGPMessage        *bgp.BGPMessage
	BGPMessagePayload []byte
	isLocal           bool
	isAddPath         bool
}

func parseBGP4MPMessage(hdr *BGP4MPHeader, isLocal bool, isAddPath bool, data []byte) (*BGP4MPMessage, error) {
	m := &BGP4MPMessage{
		BGP4MPHeader: hdr,
		isLocal:      isLocal,
		isAddPath:    isAddPath,
	}
	rest, err := m.decodeFromBytes(data)
	if err != nil {
		return nil, err
	}

	if len(rest) < bgp.BGP_HEADER_LENGTH {
		return nil, fmt.Errorf("not all BGP4MPMessageAS4 bytes available")
	}

	msg, err := bgp.ParseBGPMessage(rest)
	if err != nil {
		return nil, err
	}
	m.BGPMessage = msg
	return m, nil
}

func (m *BGP4MPMessage) Serialize() ([]byte, error) {
	buf, err := m.serialize()
	if err != nil {
		return nil, err
	}
	if m.BGPMessagePayload != nil {
		return append(buf, m.BGPMessagePayload...), nil
	}
	bbuf, err := m.BGPMessage.Serialize()
	if err != nil {
		return nil, err
	}
	return append(buf, bbuf...), nil
}

func NewBGP4MPMessage(peeras, localas uint32, intfindex uint16, peerip, localip netip.Addr, isAS4 bool, msg *bgp.BGPMessage) (*BGP4MPMessage, error) {
	header, err := newBGP4MPHeader(peeras, localas, intfindex, peerip, localip, isAS4)
	if err != nil {
		return nil, err
	}
	return &BGP4MPMessage{
		BGP4MPHeader: header,
		BGPMessage:   msg,
	}, nil
}

func NewBGP4MPMessageLocal(peeras, localas uint32, intfindex uint16, peerip, localip netip.Addr, isAS4 bool, msg *bgp.BGPMessage) (*BGP4MPMessage, error) {
	header, err := newBGP4MPHeader(peeras, localas, intfindex, peerip, localip, isAS4)
	if err != nil {
		return nil, err
	}
	return &BGP4MPMessage{
		BGP4MPHeader: header,
		BGPMessage:   msg,
		isLocal:      true,
	}, nil
}

func NewBGP4MPMessageAddPath(peeras, localas uint32, intfindex uint16, peerip, localip netip.Addr, isAS4 bool, msg *bgp.BGPMessage) (*BGP4MPMessage, error) {
	header, err := newBGP4MPHeader(peeras, localas, intfindex, peerip, localip, isAS4)
	if err != nil {
		return nil, err
	}
	return &BGP4MPMessage{
		BGP4MPHeader: header,
		BGPMessage:   msg,
		isAddPath:    true,
	}, nil
}

func NewBGP4MPMessageLocalAddPath(peeras, localas uint32, intfindex uint16, peerip, localip netip.Addr, isAS4 bool, msg *bgp.BGPMessage) (*BGP4MPMessage, error) {
	header, err := newBGP4MPHeader(peeras, localas, intfindex, peerip, localip, isAS4)
	if err != nil {
		return nil, err
	}
	return &BGP4MPMessage{
		BGP4MPHeader: header,
		BGPMessage:   msg,
		isLocal:      true,
		isAddPath:    true,
	}, nil
}

func (m *BGP4MPMessage) String() string {
	title := "BGP4MP_MSG"
	if m.isAS4 {
		title += "_AS4"
	}
	if m.isLocal {
		title += "_LOCAL"
	}
	if m.isAddPath {
		title += "_ADDPATH"
	}
	return fmt.Sprintf("%s: PeerAS [%d] LocalAS [%d] InterfaceIndex [%d] PeerIP [%s] LocalIP [%s] BGPMessage [%v]", title, m.PeerAS, m.LocalAS, m.InterfaceIndex, m.PeerIpAddress, m.LocalIpAddress, m.BGPMessage)
}

// This function can be passed into a bufio.Scanner.Split() to read buffered mrt msgs
func SplitMrt(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if cap(data) < MRT_COMMON_HEADER_LEN { // read more
		return 0, nil, nil
	}
	hdr, errh := ParseHeader(data[:MRT_COMMON_HEADER_LEN])
	if errh != nil {
		return 0, nil, errh
	}
	totlen := int(hdr.Len + MRT_COMMON_HEADER_LEN)
	if len(data) < totlen { // need to read more
		return 0, nil, nil
	}
	return totlen, data[:totlen], nil
}

func ParseBody(data []byte, h *MRTHeader) (*MRTMessage, error) {
	if len(data) < int(h.Len) {
		return nil, fmt.Errorf("not all MRT message bytes available. expected: %d, actual: %d", int(h.Len), len(data))
	}
	var err error
	var body Body
	msg := &MRTMessage{Header: *h}
	switch h.Type {
	case TABLE_DUMPv2:
		subType := MRTSubTypeTableDumpv2(h.SubType)
		rf := bgp.Family(0)
		isAddPath := false
		switch subType {
		case PEER_INDEX_TABLE:
			body, err = parsePeerIndexTable(data)
		case RIB_IPV4_UNICAST:
			rf = bgp.RF_IPv4_UC
		case RIB_IPV4_MULTICAST:
			rf = bgp.RF_IPv4_MC
		case RIB_IPV6_UNICAST:
			rf = bgp.RF_IPv6_UC
		case RIB_IPV6_MULTICAST:
			rf = bgp.RF_IPv6_MC
		case RIB_GENERIC:
		case GEO_PEER_TABLE:
			body, err = parseGeoPeerTable(data)
		case RIB_IPV4_UNICAST_ADDPATH:
			rf = bgp.RF_IPv4_UC
			isAddPath = true
		case RIB_IPV4_MULTICAST_ADDPATH:
			rf = bgp.RF_IPv4_MC
			isAddPath = true
		case RIB_IPV6_UNICAST_ADDPATH:
			rf = bgp.RF_IPv6_UC
			isAddPath = true
		case RIB_IPV6_MULTICAST_ADDPATH:
			rf = bgp.RF_IPv6_MC
			isAddPath = true
		case RIB_GENERIC_ADDPATH:
			isAddPath = true
		default:
			return nil, fmt.Errorf("unsupported table dumpv2 subtype: %v", subType)
		}

		if body == nil {
			body, err = parseRib(data, rf, isAddPath)
		}
	case BGP4MP:
		subType := MRTSubTypeBGP4MP(h.SubType)
		isAS4 := true
		switch subType {
		case STATE_CHANGE:
			isAS4 = false
			fallthrough
		case STATE_CHANGE_AS4:
			body, err = parseBGP4MPStateChange(&BGP4MPHeader{isAS4: isAS4}, data)
		case MESSAGE:
			isAS4 = false
			fallthrough
		case MESSAGE_AS4:
			body, err = parseBGP4MPMessage(&BGP4MPHeader{isAS4: isAS4}, false, false, data)
		case MESSAGE_LOCAL:
			isAS4 = false
			fallthrough
		case MESSAGE_AS4_LOCAL:
			body, err = parseBGP4MPMessage(&BGP4MPHeader{isAS4: isAS4}, true, false, data)
		case MESSAGE_ADDPATH:
			isAS4 = false
			fallthrough
		case MESSAGE_AS4_ADDPATH:
			body, err = parseBGP4MPMessage(&BGP4MPHeader{isAS4: isAS4}, false, true, data)
		case MESSAGE_LOCAL_ADDPATH:
			isAS4 = false
			fallthrough
		case MESSAGE_AS4_LOCAL_ADDPATH:
			body, err = parseBGP4MPMessage(&BGP4MPHeader{isAS4: isAS4}, true, true, data)
		default:
			return nil, fmt.Errorf("unsupported bgp4mp subtype: %v", subType)
		}
	default:
		return nil, fmt.Errorf("unsupported type: %v", h.Type)
	}

	if err != nil {
		return nil, err
	}
	msg.Body = body
	return msg, nil
}
