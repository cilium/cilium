package nlenc

import "encoding/binary"

// NativeEndian returns the native byte order of this system.
func NativeEndian() binary.ByteOrder {
	// Determine endianness by storing a uint16 in a byte slice.
	b := Uint16Bytes(1)
	if b[0] == 1 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}
