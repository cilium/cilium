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
	mapIdx := int32(0x46504265)
	a := (*[4]byte)(unsafe.Pointer(&mapFD))
	b := (*[4]byte)(unsafe.Pointer(&mapIdx))
	immProg := []byte{
		0x18, 0x12, 0x00, 0x00, a[0], a[1], a[2], a[3],
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xb7, 0x03, 0x00, 0x00, b[0], b[1], b[2], b[3],
		0x85, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
		0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	prog := getEntryProgInstructions(mapFD, mapIdx)
	var buf bytes.Buffer
	if err := prog.Marshal(&buf, binary.LittleEndian); err != nil {
		t.Fatal(err)
	}

	if insnsProg := buf.Bytes(); !bytes.Equal(insnsProg, immProg) {
		t.Errorf("Marshalled entry program does not match immediate encoding:\ngot:\n%s\nwant:\n%s",
			hex.Dump(insnsProg), hex.Dump(immProg))
	}
}
