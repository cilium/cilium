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

package rtr

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	RPKI_DEFAULT_PORT = 323
)

const (
	RTR_SERIAL_NOTIFY = iota
	RTR_SERIAL_QUERY
	RTR_RESET_QUERY
	RTR_CACHE_RESPONSE
	RTR_IPV4_PREFIX
	_
	RTR_IPV6_PREFIX
	RTR_END_OF_DATA
	RTR_CACHE_RESET
	_
	RTR_ERROR_REPORT
)

const (
	RTR_SERIAL_NOTIFY_LEN         = 12
	RTR_SERIAL_QUERY_LEN          = 12
	RTR_RESET_QUERY_LEN           = 8
	RTR_CACHE_RESPONSE_LEN        = 8
	RTR_IPV4_PREFIX_LEN           = 20
	RTR_IPV6_PREFIX_LEN           = 32
	RTR_END_OF_DATA_LEN           = 12
	RTR_CACHE_RESET_LEN           = 8
	RTR_MIN_LEN                   = 8
	RTR_ERROR_REPORT_ERR_PDU_LEN  = 4
	RTR_ERROR_REPORT_ERR_TEXT_LEN = 4
)

const (
	WITHDRAWAL uint8 = iota
	ANNOUNCEMENT
)

const (
	CORRUPT_DATA uint16 = iota
	INTERNAL_ERROR
	NO_DATA_AVAILABLE
	INVALID_REQUEST
	UNSUPPORTED_PROTOCOL_VERSION
	UNSUPPORTED_PDU_TYPE
	WITHDRAWAL_OF_UNKNOWN_RECORD
	DUPLICATE_ANNOUNCEMENT_RECORD
)

type RTRMessage interface {
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
}

type RTRCommon struct {
	Version      uint8
	Type         uint8
	SessionID    uint16
	Len          uint32
	SerialNumber uint32
}

func (m *RTRCommon) DecodeFromBytes(data []byte) error {
	if len(data) < RTR_SERIAL_NOTIFY_LEN {
		return errors.New("data too short for RTRCommon")
	}
	m.Version = data[0]
	m.Type = data[1]
	m.SessionID = binary.BigEndian.Uint16(data[2:4])
	m.Len = binary.BigEndian.Uint32(data[4:8])
	m.SerialNumber = binary.BigEndian.Uint32(data[8:12])
	return nil
}

func (m *RTRCommon) Serialize() ([]byte, error) {
	data := make([]byte, m.Len)
	data[0] = m.Version
	data[1] = m.Type
	binary.BigEndian.PutUint16(data[2:4], m.SessionID)
	binary.BigEndian.PutUint32(data[4:8], m.Len)
	binary.BigEndian.PutUint32(data[8:12], m.SerialNumber)
	return data, nil
}

type RTRSerialNotify struct {
	RTRCommon
}

func NewRTRSerialNotify(id uint16, sn uint32) *RTRSerialNotify {
	return &RTRSerialNotify{
		RTRCommon{
			Type:         RTR_SERIAL_NOTIFY,
			SessionID:    id,
			Len:          RTR_SERIAL_NOTIFY_LEN,
			SerialNumber: sn,
		},
	}
}

type RTRSerialQuery struct {
	RTRCommon
}

func NewRTRSerialQuery(id uint16, sn uint32) *RTRSerialQuery {
	return &RTRSerialQuery{
		RTRCommon{
			Type:         RTR_SERIAL_QUERY,
			SessionID:    id,
			Len:          RTR_SERIAL_QUERY_LEN,
			SerialNumber: sn,
		},
	}
}

type RTRReset struct {
	Version uint8
	Type    uint8
	Len     uint32
}

func (m *RTRReset) DecodeFromBytes(data []byte) error {
	if len(data) < RTR_RESET_QUERY_LEN {
		return errors.New("data too short for RTRReset")
	}
	m.Version = data[0]
	m.Type = data[1]
	m.Len = binary.BigEndian.Uint32(data[4:8])
	return nil
}

func (m *RTRReset) Serialize() ([]byte, error) {
	data := make([]byte, m.Len)
	data[0] = m.Version
	data[1] = m.Type
	binary.BigEndian.PutUint32(data[4:8], m.Len)
	return data, nil
}

type RTRResetQuery struct {
	RTRReset
}

func NewRTRResetQuery() *RTRResetQuery {
	return &RTRResetQuery{
		RTRReset{
			Type: RTR_RESET_QUERY,
			Len:  RTR_RESET_QUERY_LEN,
		},
	}
}

type RTRCacheResponse struct {
	Version   uint8
	Type      uint8
	SessionID uint16
	Len       uint32
}

func (m *RTRCacheResponse) DecodeFromBytes(data []byte) error {
	if len(data) < RTR_CACHE_RESPONSE_LEN {
		return errors.New("data too short for RTRCacheResponse")
	}
	m.Version = data[0]
	m.Type = data[1]
	m.SessionID = binary.BigEndian.Uint16(data[2:4])
	m.Len = binary.BigEndian.Uint32(data[4:8])
	return nil
}

func (m *RTRCacheResponse) Serialize() ([]byte, error) {
	data := make([]byte, m.Len)
	data[0] = m.Version
	data[1] = m.Type
	binary.BigEndian.PutUint16(data[2:4], m.SessionID)
	binary.BigEndian.PutUint32(data[4:8], m.Len)
	return data, nil
}

func NewRTRCacheResponse(id uint16) *RTRCacheResponse {
	return &RTRCacheResponse{
		Type:      RTR_CACHE_RESPONSE,
		SessionID: id,
		Len:       RTR_CACHE_RESPONSE_LEN,
	}
}

type RTRIPPrefix struct {
	Version   uint8
	Type      uint8
	Len       uint32
	Flags     uint8
	PrefixLen uint8
	MaxLen    uint8
	Prefix    netip.Addr
	AS        uint32
}

func (m *RTRIPPrefix) DecodeFromBytes(data []byte) error {
	if len(data) < RTR_IPV4_PREFIX_LEN {
		return errors.New("data too short for RTRIPPrefix")
	}
	m.Version = data[0]
	m.Type = data[1]
	m.Len = binary.BigEndian.Uint32(data[4:8])
	m.Flags = data[8]
	m.PrefixLen = data[9]
	m.MaxLen = data[10]
	if m.Type == RTR_IPV4_PREFIX {
		m.Prefix, _ = netip.AddrFromSlice(data[12:16])
		m.AS = binary.BigEndian.Uint32(data[16:20])
	} else {
		if len(data) < RTR_IPV6_PREFIX_LEN {
			return errors.New("data too short for RTRIPPrefix")
		}
		m.Prefix, _ = netip.AddrFromSlice(data[12:28])
		m.AS = binary.BigEndian.Uint32(data[28:32])
	}
	return nil
}

func (m *RTRIPPrefix) Serialize() ([]byte, error) {
	data := make([]byte, m.Len)
	data[0] = m.Version
	data[1] = m.Type
	binary.BigEndian.PutUint32(data[4:8], m.Len)
	data[8] = m.Flags
	data[9] = m.PrefixLen
	data[10] = m.MaxLen
	if m.Type == RTR_IPV4_PREFIX {
		copy(data[12:16], m.Prefix.AsSlice())
		binary.BigEndian.PutUint32(data[16:20], m.AS)
	} else {
		copy(data[12:28], m.Prefix.AsSlice())
		binary.BigEndian.PutUint32(data[28:32], m.AS)
	}
	return data, nil
}

func NewRTRIPPrefix(prefix netip.Addr, prefixLen, maxLen uint8, as uint32, flags uint8) *RTRIPPrefix {
	var pduType uint8
	var pduLen uint32
	if prefix.Is4() && prefixLen <= 32 {
		pduType = RTR_IPV4_PREFIX
		pduLen = RTR_IPV4_PREFIX_LEN
	} else if prefix.Is6() && prefixLen <= 128 {
		pduType = RTR_IPV6_PREFIX
		pduLen = RTR_IPV6_PREFIX_LEN
	} else {
		// TODO: return error; !prefix.IsValid() or invalid prefix length
		return nil
	}

	return &RTRIPPrefix{
		Type:      pduType,
		Len:       pduLen,
		Flags:     flags,
		PrefixLen: prefixLen,
		MaxLen:    maxLen,
		Prefix:    prefix,
		AS:        as,
	}
}

type RTREndOfData struct {
	RTRCommon
}

func NewRTREndOfData(id uint16, sn uint32) *RTREndOfData {
	return &RTREndOfData{
		RTRCommon{
			Type:         RTR_END_OF_DATA,
			SessionID:    id,
			Len:          RTR_END_OF_DATA_LEN,
			SerialNumber: sn,
		},
	}
}

type RTRCacheReset struct {
	RTRReset
}

func NewRTRCacheReset() *RTRCacheReset {
	return &RTRCacheReset{
		RTRReset{
			Type: RTR_CACHE_RESET,
			Len:  RTR_CACHE_RESET_LEN,
		},
	}
}

type RTRErrorReport struct {
	Version   uint8
	Type      uint8
	ErrorCode uint16
	Len       uint32
	PDULen    uint32
	PDU       []byte
	TextLen   uint32
	Text      []byte
}

func (m *RTRErrorReport) DecodeFromBytes(data []byte) error {
	if len(data) < 12 {
		return errors.New("data too short for RTRErrorReport")
	}
	m.Version = data[0]
	m.Type = data[1]
	m.ErrorCode = binary.BigEndian.Uint16(data[2:4])
	m.Len = binary.BigEndian.Uint32(data[4:8])
	// Basic validation: the on-wire Length field must be sane and within the
	// provided buffer to avoid excessive allocations.
	if m.Len < 16 {
		return errors.New("data too short for RTRErrorReport")
	}
	if uint32(len(data)) < m.Len {
		return errors.New("data too short for RTRErrorReport")
	}
	data = data[:m.Len]
	m.PDULen = binary.BigEndian.Uint32(data[8:12])
	// Need PDULen bytes for the erroneous PDU plus 4 bytes for TextLen.
	if m.PDULen > uint32(len(data)-12-4) {
		return errors.New("data too short for RTRErrorReport")
	}
	m.PDU = make([]byte, m.PDULen)
	copy(m.PDU, data[12:12+m.PDULen])
	textLenOffset := 12 + int(m.PDULen)
	m.TextLen = binary.BigEndian.Uint32(data[textLenOffset : textLenOffset+4])
	textOffset := textLenOffset + 4
	if m.TextLen > uint32(len(data)-textOffset) {
		return errors.New("data too short for RTRErrorReport")
	}
	// RFC6810/8210 layout: 16 + PDULen + TextLen.
	if uint64(m.Len) != 16+uint64(m.PDULen)+uint64(m.TextLen) {
		return errors.New("invalid RTRErrorReport length")
	}
	m.Text = make([]byte, m.TextLen)
	copy(m.Text, data[textOffset:textOffset+int(m.TextLen)])
	return nil
}

func (m *RTRErrorReport) Serialize() ([]byte, error) {
	data := make([]byte, m.Len)
	data[0] = m.Version
	data[1] = m.Type
	binary.BigEndian.PutUint16(data[2:4], m.ErrorCode)
	binary.BigEndian.PutUint32(data[4:8], m.Len)
	binary.BigEndian.PutUint32(data[8:12], m.PDULen)
	copy(data[12:], m.PDU)
	binary.BigEndian.PutUint32(data[12+m.PDULen:16+m.PDULen], m.TextLen)
	copy(data[16+m.PDULen:], m.Text)
	return data, nil
}

func NewRTRErrorReport(errCode uint16, errPDU []byte, errMsg []byte) *RTRErrorReport {
	pdu := &RTRErrorReport{Type: RTR_ERROR_REPORT, ErrorCode: errCode}
	if errPDU != nil {
		if errPDU[1] == RTR_ERROR_REPORT {
			return nil
		}
		pdu.PDULen = uint32(len(errPDU))
		pdu.PDU = errPDU
	}
	if errMsg != nil {
		pdu.Text = errMsg
		pdu.TextLen = uint32(len(errMsg))
	}
	pdu.Len = uint32(RTR_MIN_LEN) + uint32(RTR_ERROR_REPORT_ERR_PDU_LEN) + pdu.PDULen + uint32(RTR_ERROR_REPORT_ERR_TEXT_LEN) + pdu.TextLen
	return pdu
}

func ParseRTR(data []byte) (RTRMessage, error) {
	if len(data) < RTR_MIN_LEN {
		return nil, fmt.Errorf("not all bytes are available for RTR message")
	}
	var msg RTRMessage
	switch data[1] {
	case RTR_SERIAL_NOTIFY:
		msg = &RTRSerialNotify{}
	case RTR_SERIAL_QUERY:
		msg = &RTRSerialQuery{}
	case RTR_RESET_QUERY:
		msg = &RTRResetQuery{}
	case RTR_CACHE_RESPONSE:
		msg = &RTRCacheResponse{}
	case RTR_IPV4_PREFIX:
		msg = &RTRIPPrefix{}
	case RTR_IPV6_PREFIX:
		msg = &RTRIPPrefix{}
	case RTR_END_OF_DATA:
		msg = &RTREndOfData{}
	case RTR_CACHE_RESET:
		msg = &RTRCacheReset{}
	case RTR_ERROR_REPORT:
		msg = &RTRErrorReport{}
	default:
		return nil, fmt.Errorf("unknown RTR message type %d", data[1])
	}
	err := msg.DecodeFromBytes(data)
	return msg, err
}
