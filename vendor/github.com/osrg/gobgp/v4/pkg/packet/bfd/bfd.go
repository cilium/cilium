package bfd

import (
	"encoding"
	"encoding/binary"
	"errors"
)

//go:generate stringer -type=DiagnosticType,StateType -linecomment -output=bfd_types_string.go

type StateType uint8

type DiagnosticType uint8

// A diagnostic code specifying the local system's reason for the
// last change in session state.
const (
	DiagnosticNoDiagnostic                DiagnosticType = iota // no diagnostic
	DiagnosticControlDetectionTimeExpired                       // control detection time expired
	DiagnosticEchoFunctionFailed                                // echo function failed
	DiagnosticNeighborSignaledSessionDown                       // neighbor signaled session down
	DiagnosticForwardingPlaneReset                              // forwarding plane reset
	DiagnosticPathDown                                          // path down
	DiagnosticConcatenatedPathDown                              // concatenated path down
	DiagnosticAdministrativelyDown                              // administratively down
	DiagnosticReverseConcatenatedPathDown                       // reverse concatenated path down

	DiagnosticReservedStart DiagnosticType = 9  // reserved (9-31)
	DiagnosticReservedEnd   DiagnosticType = 31 // reserved (9-31)
)

const (
	StateAdminDown StateType = iota // admin down
	StateDown                       // down
	StateInit                       // init
	StateUp                         // up
)

const (
	packetSizeMin = 24
)

var (
	ErrInvalidPacketLength = errors.New("invalid packet length")
	ErrInvalidHeader       = errors.New("invalid header")
	ErrInvalidVersion      = errors.New("invalid version")
	ErrInvalidDiagnostic   = errors.New("invalid diagnostic")
	ErrInvalidState        = errors.New("invalid state")
)

type BFDHeader struct {
	Version               uint8
	Diagnostic            DiagnosticType
	State                 StateType
	Poll                  bool
	Final                 bool
	DetectTimeMultiplier  uint8
	MyDiscriminator       uint32
	YourDiscriminator     uint32
	DesiredMinTxInterval  uint32
	RequiredMinRxInterval uint32
}

func (h *BFDHeader) Validate() error {
	if h.Version > 7 {
		return ErrInvalidVersion
	}
	if h.Diagnostic > 31 {
		return ErrInvalidDiagnostic
	}
	if h.State > 3 {
		return ErrInvalidState
	}
	return nil
}

var (
	_ encoding.BinaryMarshaler   = &BFDHeader{}
	_ encoding.BinaryUnmarshaler = &BFDHeader{}
)

/*
    0               1               2               3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Vers |  Diag   |Sta|P|F|C|A|D|M|  Detect Mult  |    Length     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       My Discriminator                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Your Discriminator                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Desired Min TX Interval                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   Required Min RX Interval                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 Required Min Echo RX Interval                 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

func byteToBool(b byte) bool {
	return b != 0
}

func boolToByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

func (h *BFDHeader) UnmarshalBinary(buf []byte) error {
	if len(buf) < packetSizeMin {
		return ErrInvalidPacketLength
	}

	if len(buf) != int(buf[3]) {
		return ErrInvalidHeader
	}

	h.Version = buf[0] >> 5
	h.Diagnostic = DiagnosticType(buf[0] & 0x1f)
	h.State = StateType(buf[1] >> 6)
	h.Poll = byteToBool(buf[1] >> 5 & 1)
	h.Final = byteToBool(buf[1] >> 4 & 1)
	// ignore other flags

	h.DetectTimeMultiplier = buf[2]

	h.MyDiscriminator = binary.BigEndian.Uint32(buf[4:])
	h.YourDiscriminator = binary.BigEndian.Uint32(buf[8:])
	h.DesiredMinTxInterval = binary.BigEndian.Uint32(buf[12:])
	h.RequiredMinRxInterval = binary.BigEndian.Uint32(buf[16:])
	// ignore other variables

	return nil
}

func (h *BFDHeader) MarshalBinary() ([]byte, error) {
	buf := make([]byte, packetSizeMin)

	if err := h.Validate(); err != nil {
		return nil, err
	}

	buf[0] = h.Version<<5 | byte(h.Diagnostic)&0x1f
	buf[1] = byte(h.State)<<6 | boolToByte(h.Poll)<<5 | boolToByte(h.Final)<<4
	buf[2] = h.DetectTimeMultiplier
	buf[3] = byte(packetSizeMin)

	binary.BigEndian.PutUint32(buf[4:], h.MyDiscriminator)
	binary.BigEndian.PutUint32(buf[8:], h.YourDiscriminator)
	binary.BigEndian.PutUint32(buf[12:], h.DesiredMinTxInterval)
	binary.BigEndian.PutUint32(buf[16:], h.RequiredMinRxInterval)

	return buf, nil
}
