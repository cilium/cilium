package ethernet

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	// VLANNone is a special VLAN ID which indicates that no VLAN is being
	// used in a Frame.  In this case, the VLAN's other fields may be used
	// to indicate a Frame's priority.
	VLANNone = 0x000

	// VLANMax is a reserved VLAN ID which may indicate a wildcard in some
	// management systems, but may not be configured or transmitted in a
	// VLAN tag.
	VLANMax = 0xfff
)

var (
	// ErrInvalidVLAN is returned when a VLAN tag is invalid due to one of the
	// following reasons:
	//   - Priority of greater than 7 is detected
	//   - ID of greater than 4094 (0xffe) is detected
	//   - A customer VLAN does not follow a service VLAN (when using Q-in-Q)
	ErrInvalidVLAN = errors.New("invalid VLAN")
)

// Priority is an IEEE P802.1p priority level.  Priority can be any value from
// 0 to 7.
//
// It is important to note that priority 1 (PriorityBackground) actually has
// a lower priority than 0 (PriorityBestEffort).  All other Priority constants
// indicate higher priority as the integer values increase.
type Priority uint8

// IEEE P802.1p recommended priority levels.  Note that PriorityBackground has
// a lower priority than PriorityBestEffort.
const (
	PriorityBackground           Priority = 1
	PriorityBestEffort           Priority = 0
	PriorityExcellentEffort      Priority = 2
	PriorityCriticalApplications Priority = 3
	PriorityVideo                Priority = 4
	PriorityVoice                Priority = 5
	PriorityInternetworkControl  Priority = 6
	PriorityNetworkControl       Priority = 7
)

// A VLAN is an IEEE 802.1Q Virtual LAN (VLAN) tag.  A VLAN contains
// information regarding traffic priority and a VLAN identifier for
// a given Frame.
type VLAN struct {
	// Priority specifies a IEEE P802.1p priority level.  Priority can be any
	// value from 0 to 7.
	Priority Priority

	// DropEligible indicates if a Frame is eligible to be dropped in the
	// presence of network congestion.
	DropEligible bool

	// ID specifies the VLAN ID for a Frame.  ID can be any value from 0 to
	// 4094 (0x000 to 0xffe), allowing up to 4094 VLANs.
	//
	// If ID is 0 (0x000, VLANNone), no VLAN is specified, and the other fields
	// simply indicate a Frame's priority.
	ID uint16
}

// MarshalBinary allocates a byte slice and marshals a VLAN into binary form.
func (v *VLAN) MarshalBinary() ([]byte, error) {
	b := make([]byte, 2)
	_, err := v.read(b)
	return b, err
}

// read reads data from a VLAN into b.  read is used to marshal a VLAN into
// binary form, but does not allocate on its own.
func (v *VLAN) read(b []byte) (int, error) {
	// Check for VLAN priority in valid range
	if v.Priority > PriorityNetworkControl {
		return 0, ErrInvalidVLAN
	}

	// Check for VLAN ID in valid range
	if v.ID >= VLANMax {
		return 0, ErrInvalidVLAN
	}

	// 3 bits: priority
	ub := uint16(v.Priority) << 13

	// 1 bit: drop eligible
	var drop uint16
	if v.DropEligible {
		drop = 1
	}
	ub |= drop << 12

	// 12 bits: VLAN ID
	ub |= v.ID

	binary.BigEndian.PutUint16(b, ub)
	return 2, nil
}

// UnmarshalBinary unmarshals a byte slice into a VLAN.
func (v *VLAN) UnmarshalBinary(b []byte) error {
	// VLAN tag is always 2 bytes
	if len(b) != 2 {
		return io.ErrUnexpectedEOF
	}

	//  3 bits: priority
	//  1 bit : drop eligible
	// 12 bits: VLAN ID
	ub := binary.BigEndian.Uint16(b[0:2])
	v.Priority = Priority(uint8(ub >> 13))
	v.DropEligible = ub&0x1000 != 0
	v.ID = ub & 0x0fff

	// Check for VLAN ID in valid range
	if v.ID >= VLANMax {
		return ErrInvalidVLAN
	}

	return nil
}
