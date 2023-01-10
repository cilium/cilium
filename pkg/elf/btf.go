// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package elf

import (
	"bufio"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

type btfHeader struct {
	// Must always be 0xeB9F.
	Magic uint16

	// Padding for fields we're not interested in.
	_ [2]byte

	// Length of this header struct.
	HeaderLength uint32

	_ [8]byte

	// StrOff represents the offset of the BTF string section
	// relative to end of this header.
	StrOff uint32
	// StrLen is the length in bytes of the BTF string section.
	StrLen uint32
}

// readBTFHeader reads the BTF header from a r pointing at the start of the
// .BTF ELF section.
func readBTFHeader(btfSec *elf.Section, bo binary.ByteOrder) (*btfHeader, error) {
	rs := btfSec.Open()

	var h btfHeader
	if err := binary.Read(rs, bo, &h); err != nil {
		return nil, err
	}
	if h.Magic != 0xeB9F {
		return nil, fmt.Errorf("expected 0xeB9F Magic value, got: %x", h.Magic)
	}

	return &h, nil
}

// findBTFSymbols walks through the string table in the .BTF section.
// Each encountered string symbol that is also already present in 'symbols'
// gets its offsetBTF field populated with its absolute position in the ELF.
func findBTFSymbols(symbols map[string]symbol, btfSec *elf.Section, h *btfHeader) error {
	rs := btfSec.Open()

	// Offset from the start of the .BTF section to the BTF string table.
	btfStrTabOff := h.HeaderLength + h.StrOff

	// Seek to the location of the BTF string table.
	if _, err := rs.Seek(int64(btfStrTabOff), io.SeekStart); err != nil {
		return fmt.Errorf("seeking to BTF string table: %w", err)
	}

	// Track the reader's position to obtain symbol offsets.
	var rdrOff uint64
	r := bufio.NewReader(rs)
	for {
		b, err := r.ReadBytes(nullTerminator)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("reading BTF string table: %w", err)
		}

		read := uint64(len(b))
		rdrOff += uint64(read)

		// Strip trailing NUL byte and convert to string.
		// ReadBytes always includes delim when err == nil, so this is safe.
		s := string(b[:len(b)-1])

		// Skip empty strings.
		if s == "" {
			continue
		}

		// Look up the string in the offsets gathered from the ELF symbol table.
		// Any matches belong to an ELF symbol and need to be replaced later.
		if so, ok := symbols[s]; ok {
			// btfSec.Offset is the absolute offset of the BTF section in the ELF.
			// btfStrTabOff is the offset of the BTF string table with in the section.
			// rdrOff points to the end of the string within the (binary) string table.
			// Subtract the amount of bytes read during this iteration, we want the offset
			// to the start of the symbol.
			so.offsetBTF = btfSec.Offset + uint64(btfStrTabOff) + rdrOff - read
			symbols[s] = so
		}
	}

	return nil
}
