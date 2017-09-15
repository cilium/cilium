// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// This file tests some of the functionality provided in the ip4.go

package layers

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"

	"github.com/google/gopacket"
)

// Test the function getIPv4OptionSize when the ipv4 has no options
func TestGetIPOptLengthNoOpt(t *testing.T) {
	ip := IPv4{}
	length := ip.getIPv4OptionSize()
	if length != 0 {
		t.Fatalf("Empty option list should have 0 length.  Actual %d", length)
	}
}

// Test the function getIPv4OptionSize when the ipv4 has end of list option
func TestGetIPOptLengthEndOfList(t *testing.T) {
	ip := IPv4{}
	ip.Options = append(ip.Options, IPv4Option{OptionType: 0, OptionLength: 1})
	length := ip.getIPv4OptionSize()
	if length != 4 {
		t.Fatalf("After padding, the list should have 4 length.  Actual %d", length)
	}
}

// Test the function getIPv4OptionSize when the ipv4 has padding and end of list option
func TestGetIPOptLengthPaddingEndOfList(t *testing.T) {
	ip := IPv4{}
	ip.Options = append(ip.Options, IPv4Option{OptionType: 1, OptionLength: 1})
	ip.Options = append(ip.Options, IPv4Option{OptionType: 0, OptionLength: 1})
	length := ip.getIPv4OptionSize()
	if length != 4 {
		t.Fatalf("After padding, the list should have 4 length.  Actual %d", length)
	}
}

// Test the function getIPv4OptionSize when the ipv4 has some non-trivial option and end of list option
func TestGetIPOptLengthOptionEndOfList(t *testing.T) {
	ip := IPv4{}
	someByte := make([]byte, 8)
	ip.Options = append(ip.Options, IPv4Option{OptionType: 2, OptionLength: 10, OptionData: someByte})
	ip.Options = append(ip.Options, IPv4Option{OptionType: 0, OptionLength: 1})
	length := ip.getIPv4OptionSize()
	if length != 12 {
		t.Fatalf("The list should have 12 length.  Actual %d", length)
	}
}

// Tests that the Options slice is properly reset before parsing new data
func TestIPOptResetDuringDecoding(t *testing.T) {
	ip := &IPv4{
		Options: []IPv4Option{{OptionType: 42, OptionLength: 4, OptionData: make([]byte, 2)}},
	}

	ipWithoutOptions := &IPv4{
		SrcIP:    net.IPv4(192, 168, 1, 1),
		DstIP:    net.IPv4(192, 168, 1, 1),
		Protocol: IPProtocolTCP,
	}

	ipBytes, err := serialize(ipWithoutOptions)

	if err != nil {
		t.Fatalf("Failed to serialize ip layer: %v", err)
	}

	err = ip.DecodeFromBytes(ipBytes, gopacket.NilDecodeFeedback)

	if err != nil {
		t.Fatalf("Failed to deserialize ip layer: %v", err)
	}

	if len(ip.Options) > 0 {
		t.Fatalf("Options slice has stale data from previous packet")
	}

}

func serialize(ip *IPv4) ([]byte, error) {
	buffer := gopacket.NewSerializeBuffer()
	err := ip.SerializeTo(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	})
	return buffer.Bytes(), err
}

// Test the function checksum
func TestChecksum(t *testing.T) {
	testData := []struct {
		name   string
		header string
		want   string
	}{{
		name:   "sum has two carries",
		header: "4540005800000000ff11ffff0aeb1d070aed8877",
		want:   "fffe",
	}, {
		name:   "wikipedia case",
		header: "45000073000040004011b861c0a80001c0a800c7",
		want:   "b861",
	}}

	for _, test := range testData {
		bytes, err := hex.DecodeString(test.header)
		if err != nil {
			t.Fatalf("Failed to Decode header: %v", err)
		}
		wantBytes, err := hex.DecodeString(test.want)
		if err != nil {
			t.Fatalf("Failed to decode want checksum: %v", err)
		}

		if got, want := checksum(bytes), binary.BigEndian.Uint16(wantBytes); got != want {
			t.Errorf("In test %q, got incorrect checksum: got(%x), want(%x)", test.name, got, want)
		}
	}
}
