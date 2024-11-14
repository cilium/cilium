// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"fmt"
	"net"
)

// MPTCPSubtype represents an MPTCP subtype code.
type MPTCPSubtype uint8

// MPTCP Subtypes constonts from https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xml#mptcp-option-subtypes
const (
	MPTCPSubtypeMPCAPABLE   = 0x0
	MPTCPSubtypeMPJOIN      = 0x1
	MPTCPSubtypeDSS         = 0x2
	MPTCPSubtypeADDADDR     = 0x3
	MPTCPSubtypeREMOVEADDR  = 0x4
	MPTCPSubtypeMPPRIO      = 0x5
	MPTCPSubtypeMPFAIL      = 0x6
	MPTCPSubtypeMPFASTCLOSE = 0x7
	MPTCPSubtypeMPTCPRST    = 0x8
)

func (k MPTCPSubtype) String() string {
	switch k {
	case MPTCPSubtypeMPCAPABLE:
		return "MP_CAPABLE"
	case MPTCPSubtypeMPJOIN:
		return "MP_JOIN"
	case MPTCPSubtypeDSS:
		return "DSS"
	case MPTCPSubtypeADDADDR:
		return "ADD_ADDR"
	case MPTCPSubtypeREMOVEADDR:
		return "REMOVE_ADDR"
	case MPTCPSubtypeMPPRIO:
		return "MP_PRIO"
	case MPTCPSubtypeMPFAIL:
		return "MP_FAIL"
	case MPTCPSubtypeMPFASTCLOSE:
		return "MP_FASTCLOSE"
	case MPTCPSubtypeMPTCPRST:
		return "MP_TCPRST"
	default:
		return fmt.Sprintf("Unknown(%d)", k)
	}
}

const (
	MptcpVersion0 = 0
	MptcpVersion1 = 1
)

const (
	OptionLenMpCapableSyn         = 4
	OptionLenMpCapableSynAck      = 12
	OptionLenMpCapableAck         = 20
	OptionLenMpCapableAckData     = 22
	OptionLenMpCapableAckDataCSum = 24
	OptionLenMpJoinSyn            = 12
	OptionLenMpJoinSynAck         = 16
	OptionLenMpJoinAck            = 24
	OptionLenDssAck               = 4
	OptionLenDssAck64             = 8
	OptionLenDssDSN               = 4
	OptionLenDssDSN64             = 8
	OptionLenDssSSN               = 4
	OptionLenDssDataLen           = 2
	OptionLenDssCSum              = 2
	OptionLenAddAddrv4            = 8
	OptionLenAddAddrv6            = 20
	OptionLenAddAddrPort          = 2
	OptionLenAddAddrHmac          = 8
	OptionLenRemAddr              = 4
	OptionLenMpPrio               = 3
	OptionLenMpPrioAddr           = 4
	OptionLenMpFail               = 12
	OptionLenMpFClose             = 12
	OptionLenMpTcpRst             = 4
)

// MPCapable contains the fields from the MP_CAPABLE MPTCP Option
type MPCapable struct {
	BaseLayer
	Version                uint8
	A, B, C, D, E, F, G, H bool
	SendKey                []byte
	ReceivKey              []byte
	DataLength             uint16
	Checksum               uint16
}

// MPJoin contains the fields from the MP_JOIN MPTCP Option
type MPJoin struct {
	BaseLayer
	Backup      bool
	AddrID      uint8
	ReceivToken uint32
	SendRandNum uint32
	SendHMAC    []byte
}

// Dss contains the fields from the DSS MPTCP Option
type Dss struct {
	BaseLayer
	F, m, M, a, A bool
	DataAck       []byte
	DSN           []byte
	SSN           uint32
	DataLength    uint16
	Checksum      uint16
}

// AddAddr contains the fields from the ADD_ADDR MPTCP Option
type AddAddr struct {
	BaseLayer
	IPVer    uint8
	E        bool
	AddrID   uint8
	Address  net.IP
	Port     uint16
	SendHMAC []byte
}

// RemAddr contains the fields from the REMOVE_ADDR MPTCP Option
type RemAddr struct {
	BaseLayer
	AddrIDs []uint8
}

// MPPrio contains the fields from the MP_PRIO MPTCP Option
type MPPrio struct {
	BaseLayer
	Backup bool
	AddrID uint8
}

// MPFail contains the fields from the MP_FAIL MPTCP Option
type MPFail struct {
	BaseLayer
	DSN uint64
}

// MPFClose contains the fields from the MP_FASTCLOSE MPTCP Option
type MPFClose struct {
	BaseLayer
	ReceivKey []byte
}

// MPTcpRst contains the fields from the MP_TCPRST MPTCP Option
type MPTcpRst struct {
	BaseLayer
	U, V, W, T bool
	Reason     uint8
}
