// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package connector

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"unsafe"
)

func TestEntryProgInstructions(t *testing.T) {
	mapFD := 0xaabbccdd
	tmp := (*[4]byte)(unsafe.Pointer(&mapFD))
	immProg := []byte{
		0x18, 0x12, 0x00, 0x00, tmp[0], tmp[1], tmp[2], tmp[3],
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xb7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x85, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
		0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	prog := getEntryProgInstructions(mapFD)
	var buf bytes.Buffer
	if err := prog.Marshal(&buf, binary.LittleEndian); err != nil {
		t.Fatal(err)
	}

	if insnsProg := buf.Bytes(); !bytes.Equal(insnsProg, immProg) {
		t.Errorf("Marshalled entry program does not match immediate encoding:\ngot:\n%s\nwant:\n%s",
			hex.Dump(insnsProg), hex.Dump(immProg))
	}
}
