// Package ethernet implements marshaling and unmarshaling of IEEE 802.3
// Ethernet II frames and IEEE 802.1Q VLAN tags.
package ethernet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
)

//go:generate stringer -output=string.go -type=EtherType

const (
	// minPayload is the minimum payload size for an Ethernet frame, assuming
	// that no 802.1Q VLAN tags are present.
	minPayload = 46
)

// Broadcast is a special hardware address which indicates a Frame should
// be sent to every device on a given LAN segment.
var Broadcast = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// ErrInvalidFCS is returned when Frame.UnmarshalFCS detects an incorrect
// Ethernet frame check sequence in a byte slice for a Frame.
var ErrInvalidFCS = errors.New("invalid frame check sequence")

// An EtherType is a value used to identify an upper layer protocol
// encapsulated in a Frame.
//
// A list of IANA-assigned EtherType values may be found here:
// http://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml.
type EtherType uint16

// Common EtherType values frequently used in a Frame.
const (
	EtherTypeIPv4 EtherType = 0x0800
	EtherTypeARP  EtherType = 0x0806
	EtherTypeIPv6 EtherType = 0x86DD

	// EtherTypeVLAN and EtherTypeServiceVLAN are used as 802.1Q Tag Protocol
	// Identifiers (TPIDs).
	EtherTypeVLAN        EtherType = 0x8100
	EtherTypeServiceVLAN EtherType = 0x88a8
)

// A Frame is an IEEE 802.3 Ethernet II frame.  A Frame contains information
// such as source and destination hardware addresses, zero or more optional
// 802.1Q VLAN tags, an EtherType, and payload data.
type Frame struct {
	// Destination specifies the destination hardware address for this Frame.
	//
	// If this address is set to Broadcast, the Frame will be sent to every
	// device on a given LAN segment.
	Destination net.HardwareAddr

	// Source specifies the source hardware address for this Frame.
	//
	// Typically, this is the hardware address of the network interface used to
	// send this Frame.
	Source net.HardwareAddr

	// ServiceVLAN specifies an optional 802.1Q service VLAN tag, for use with
	// 802.1ad double tagging, or "Q-in-Q". If ServiceVLAN is not nil, VLAN must
	// not be nil as well.
	//
	// Most users should leave this field set to nil and use VLAN instead.
	ServiceVLAN *VLAN

	// VLAN specifies an optional 802.1Q customer VLAN tag, which may or may
	// not be present in a Frame.  It is important to note that the operating
	// system may automatically strip VLAN tags before they can be parsed.
	VLAN *VLAN

	// EtherType is a value used to identify an upper layer protocol
	// encapsulated in this Frame.
	EtherType EtherType

	// Payload is a variable length data payload encapsulated by this Frame.
	Payload []byte
}

// MarshalBinary allocates a byte slice and marshals a Frame into binary form.
func (f *Frame) MarshalBinary() ([]byte, error) {
	b := make([]byte, f.length())
	_, err := f.read(b)
	return b, err
}

// MarshalFCS allocates a byte slice, marshals a Frame into binary form, and
// finally calculates and places a 4-byte IEEE CRC32 frame check sequence at
// the end of the slice.
//
// Most users should use MarshalBinary instead.  MarshalFCS is provided as a
// convenience for rare occasions when the operating system cannot
// automatically generate a frame check sequence for an Ethernet frame.
func (f *Frame) MarshalFCS() ([]byte, error) {
	// Frame length with 4 extra bytes for frame check sequence
	b := make([]byte, f.length()+4)
	if _, err := f.read(b); err != nil {
		return nil, err
	}

	// Compute IEEE CRC32 checksum of frame bytes and place it directly
	// in the last four bytes of the slice
	binary.BigEndian.PutUint32(b[len(b)-4:], crc32.ChecksumIEEE(b[0:len(b)-4]))
	return b, nil
}

// read reads data from a Frame into b.  read is used to marshal a Frame
// into binary form, but does not allocate on its own.
func (f *Frame) read(b []byte) (int, error) {
	// S-VLAN must also have accompanying C-VLAN.
	if f.ServiceVLAN != nil && f.VLAN == nil {
		return 0, ErrInvalidVLAN
	}

	copy(b[0:6], f.Destination)
	copy(b[6:12], f.Source)

	// Marshal each non-nil VLAN tag into bytes, inserting the appropriate
	// EtherType/TPID before each, so devices know that one or more VLANs
	// are present.
	vlans := []struct {
		vlan *VLAN
		tpid EtherType
	}{
		{vlan: f.ServiceVLAN, tpid: EtherTypeServiceVLAN},
		{vlan: f.VLAN, tpid: EtherTypeVLAN},
	}

	n := 12
	for _, vt := range vlans {
		if vt.vlan == nil {
			continue
		}

		// Add VLAN EtherType and VLAN bytes.
		binary.BigEndian.PutUint16(b[n:n+2], uint16(vt.tpid))
		if _, err := vt.vlan.read(b[n+2 : n+4]); err != nil {
			return 0, err
		}
		n += 4
	}

	// Marshal actual EtherType after any VLANs, copy payload into
	// output bytes.
	binary.BigEndian.PutUint16(b[n:n+2], uint16(f.EtherType))
	copy(b[n+2:], f.Payload)

	return len(b), nil
}

// UnmarshalBinary unmarshals a byte slice into a Frame.
func (f *Frame) UnmarshalBinary(b []byte) error {
	// Verify that both hardware addresses and a single EtherType are present
	if len(b) < 14 {
		return io.ErrUnexpectedEOF
	}

	// Track offset in packet for reading data
	n := 14

	// Continue looping and parsing VLAN tags until no more VLAN EtherType
	// values are detected
	et := EtherType(binary.BigEndian.Uint16(b[n-2 : n]))
	switch et {
	case EtherTypeServiceVLAN, EtherTypeVLAN:
		// VLAN type is hinted for further parsing.  An index is returned which
		// indicates how many bytes were consumed by VLAN tags.
		nn, err := f.unmarshalVLANs(et, b[n:])
		if err != nil {
			return err
		}

		n += nn
	default:
		// No VLANs detected.
		f.EtherType = et
	}

	// Allocate single byte slice to store destination and source hardware
	// addresses, and payload
	bb := make([]byte, 6+6+len(b[n:]))
	copy(bb[0:6], b[0:6])
	f.Destination = bb[0:6]
	copy(bb[6:12], b[6:12])
	f.Source = bb[6:12]

	// There used to be a minimum payload length restriction here, but as
	// long as two hardware addresses and an EtherType are present, it
	// doesn't really matter what is contained in the payload.  We will
	// follow the "robustness principle".
	copy(bb[12:], b[n:])
	f.Payload = bb[12:]

	return nil
}

// UnmarshalFCS computes the IEEE CRC32 frame check sequence of a Frame,
// verifies it against the checksum present in the byte slice, and finally,
// unmarshals a byte slice into a Frame.
//
// Most users should use UnmarshalBinary instead.  UnmarshalFCS is provided as
// a convenience for rare occasions when the operating system cannot
// automatically verify a frame check sequence for an Ethernet frame.
func (f *Frame) UnmarshalFCS(b []byte) error {
	// Must contain enough data for FCS, to avoid panics
	if len(b) < 4 {
		return io.ErrUnexpectedEOF
	}

	// Verify checksum in slice versus newly computed checksum
	want := binary.BigEndian.Uint32(b[len(b)-4:])
	got := crc32.ChecksumIEEE(b[0 : len(b)-4])
	if want != got {
		return ErrInvalidFCS
	}

	return f.UnmarshalBinary(b[0 : len(b)-4])
}

// length calculates the number of bytes required to store a Frame.
func (f *Frame) length() int {
	// If payload is less than the required minimum length, we zero-pad up to
	// the required minimum length
	pl := len(f.Payload)
	if pl < minPayload {
		pl = minPayload
	}

	// Add additional length if VLAN tags are needed.
	var vlanLen int
	switch {
	case f.ServiceVLAN != nil && f.VLAN != nil:
		vlanLen = 8
	case f.VLAN != nil:
		vlanLen = 4
	}

	// 6 bytes: destination hardware address
	// 6 bytes: source hardware address
	// N bytes: VLAN tags (if present)
	// 2 bytes: EtherType
	// N bytes: payload length (may be padded)
	return 6 + 6 + vlanLen + 2 + pl
}

// unmarshalVLANs unmarshals S/C-VLAN tags.  It is assumed that tpid
// is a valid S/C-VLAN TPID.
func (f *Frame) unmarshalVLANs(tpid EtherType, b []byte) (int, error) {
	// 4 or more bytes must remain for valid S/C-VLAN tag and EtherType.
	if len(b) < 4 {
		return 0, io.ErrUnexpectedEOF
	}

	// Track how many bytes are consumed by VLAN tags.
	var n int

	switch tpid {
	case EtherTypeServiceVLAN:
		vlan := new(VLAN)
		if err := vlan.UnmarshalBinary(b[n : n+2]); err != nil {
			return 0, err
		}
		f.ServiceVLAN = vlan

		// Assume that a C-VLAN immediately trails an S-VLAN.
		if EtherType(binary.BigEndian.Uint16(b[n+2:n+4])) != EtherTypeVLAN {
			return 0, ErrInvalidVLAN
		}

		// 4 or more bytes must remain for valid C-VLAN tag and EtherType.
		n += 4
		if len(b[n:]) < 4 {
			return 0, io.ErrUnexpectedEOF
		}

		// Continue to parse the C-VLAN.
		fallthrough
	case EtherTypeVLAN:
		vlan := new(VLAN)
		if err := vlan.UnmarshalBinary(b[n : n+2]); err != nil {
			return 0, err
		}

		f.VLAN = vlan
		f.EtherType = EtherType(binary.BigEndian.Uint16(b[n+2 : n+4]))
		n += 4
	default:
		panic(fmt.Sprintf("unknown VLAN TPID: %04x", tpid))
	}

	return n, nil
}
