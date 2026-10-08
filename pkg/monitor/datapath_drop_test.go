// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

func TestDropNotifyV1_Decode(t *testing.T) {
	// This check on the struct length constant is there to ensure that this
	// test is updated when the struct changes.
	require.Equal(t, 36, dropNotifyV1Len)

	testCases := []struct {
		name  string
		input DropNotify
	}{
		{
			name: "empty",
		},
		{
			name: "arbitrary",
			input: DropNotify{
				Type:     0x00,
				SubType:  0x01,
				Source:   0x02_03,
				Hash:     0x04_05_06_07,
				OrigLen:  0x08_09_0a_0b,
				CapLen:   0x0e_10,
				Version:  0x01,
				SrcLabel: 0x11_12_13_14,
				DstLabel: 0x15_16_17_18,
				DstID:    0x19_1a_1b_1c,
				Line:     0x1d_1e,
				File:     0x20,
				ExtError: 0x21,
				Ifindex:  0x22_23_24_25,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := bytes.NewBuffer(nil)
			if err := binary.Write(buf, binary.NativeEndian, tc.input); err != nil {
				t.Fatalf("Unexpected error from Write(...); got: %v", err)
			}

			output := DropNotify{}
			if err := output.Decode(buf.Bytes()); err != nil {
				t.Fatalf("Unexpected error from Decode(<bytes>); got: %v", err)
			}

			if diff := cmp.Diff(tc.input, output); diff != "" {
				t.Errorf("Unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDropNotify_Decode(t *testing.T) {
	// This check on the struct length constant is there to ensure that this
	// test is updated when the struct changes.
	require.Equal(t, 40, dropNotifyV2Len)
	require.Equal(t, 48, dropNotifyV3Len)

	testCases := []struct {
		name  string
		input DropNotify
	}{
		{
			name: "empty",
		},
		{
			name: "arbitrary",
			input: DropNotify{
				Type:      0x00,
				SubType:   0x01,
				Source:    0x02_03,
				Hash:      0x04_05_06_07,
				OrigLen:   0x08_09_0a_0b,
				CapLen:    0x0e_10,
				Version:   0x03,
				SrcLabel:  0x11_12_13_14,
				DstLabel:  0x15_16_17_18,
				DstID:     0x19_1a_1b_1c,
				Line:      0x1d_1e,
				File:      0x20,
				ExtError:  0x21,
				Ifindex:   0x22_23_24_25,
				Flags:     0x0f,
				IPTraceID: 0x99,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := bytes.NewBuffer(nil)
			if err := binary.Write(buf, binary.NativeEndian, tc.input); err != nil {
				t.Fatalf("Unexpected error from Write(...); got: %v", err)
			}

			output := DropNotify{}
			if err := output.Decode(buf.Bytes()); err != nil {
				t.Fatalf("Unexpected error from Decode(<bytes>); got: %v", err)
			}

			if diff := cmp.Diff(tc.input, output); diff != "" {
				t.Errorf("Unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDecodeDropNotify(t *testing.T) {
	testCases := []struct {
		name  string
		input any
		want  uint
	}{
		{
			name: "v1",
			input: DropNotify{
				Type:     0x00,
				SubType:  0x01,
				Source:   0x02_03,
				Hash:     0x04_05_06_07,
				OrigLen:  0x08_09_0a_0b,
				CapLen:   0x0e_10,
				Version:  0x01,
				SrcLabel: 0x11_12_13_14,
				DstLabel: 0x15_16_17_18,
				DstID:    0x19_1a_1b_1c,
				Line:     0x1d_1e,
				File:     0x20,
				ExtError: 0x21,
				Ifindex:  0x22_23_24_25,
			},
			want: dropNotifyV1Len,
		},
		{
			name: "v2",
			input: DropNotify{
				Type:     0x00,
				SubType:  0x01,
				Source:   0x02_03,
				Hash:     0x04_05_06_07,
				OrigLen:  0x08_09_0a_0b,
				CapLen:   0x0e_10,
				Version:  0x02,
				SrcLabel: 0x11_12_13_14,
				DstLabel: 0x15_16_17_18,
				DstID:    0x19_1a_1b_1c,
				Line:     0x1d_1e,
				File:     0x20,
				ExtError: 0x21,
				Ifindex:  0x22_23_24_25,
			},
			want: dropNotifyV2Len,
		},
		{
			name: "with_iptrace",
			input: DropNotify{
				Type:      0x00,
				SubType:   0x01,
				Source:    0x02_03,
				Hash:      0x04_05_06_07,
				OrigLen:   0x08_09_0a_0b,
				CapLen:    0x0e_10,
				Version:   0x03,
				SrcLabel:  0x11_12_13_14,
				DstLabel:  0x15_16_17_18,
				DstID:     0x19_1a_1b_1c,
				Line:      0x1d_1e,
				File:      0x20,
				ExtError:  0x21,
				Ifindex:   0x22_23_24_25,
				IPTraceID: 0x999,
			},
			want: dropNotifyV3Len,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := bytes.NewBuffer(nil)
			if err := binary.Write(buf, binary.NativeEndian, tc.input); err != nil {
				t.Fatalf("Unexpected error from Write(...); got: %v", err)
			}

			output := DropNotify{}
			if err := output.Decode(buf.Bytes()); err != nil {
				t.Fatalf("Unexpected error from Decode(<bytes>); got: %v", err)
			}

			if got := output.DataOffset(); got != tc.want {
				t.Fatalf("Unexpected DataOffset(); want %d, got %d", tc.want, got)
			}
		})
	}
}

func TestDecodeDropNotifyExtension(t *testing.T) {
	setTmpExtVer := func(extVer uint8, extLen uint) {
		oldLen, ok := dropNotifyExtensionLengthFromVersion[extVer]
		if !ok {
			t.Cleanup(func() { delete(dropNotifyExtensionLengthFromVersion, extVer) })
		} else {
			t.Cleanup(func() { dropNotifyExtensionLengthFromVersion[extVer] = oldLen })
		}
		dropNotifyExtensionLengthFromVersion[extVer] = extLen
	}

	setTmpExtVer(1, 4)
	setTmpExtVer(2, 8)
	setTmpExtVer(3, 16)

	tcs := []struct {
		name      string
		dn        DropNotify
		extension []uint32
	}{
		{
			name: "no extension",
			dn: DropNotify{
				Version:    3,
				ExtVersion: 0,
			},
		},
		{
			name: "extension 1",
			dn: DropNotify{
				Version:    3,
				ExtVersion: 1,
			},
			extension: []uint32{
				0xC0FFEE,
			},
		},
		{
			name: "extension 2",
			dn: DropNotify{
				Version:    3,
				ExtVersion: 2,
			},
			extension: []uint32{
				0xC0FFEE,
				0xDECAFBAD,
			},
		},
		{
			name: "extension 2",
			dn: DropNotify{
				Version:    3,
				ExtVersion: 3,
			},
			extension: []uint32{
				0xC0FFEE,
				0xDECAFBAD,
				0xFA1AFE1,
				0xF00DF00D,
			},
		},
	}

	for _, tc := range tcs {
		buf := bytes.NewBuffer(nil)
		err := binary.Write(buf, binary.NativeEndian, tc.dn)
		require.NoError(t, err)
		err = binary.Write(buf, binary.NativeEndian, tc.extension)
		require.NoError(t, err)
		err = binary.Write(buf, binary.NativeEndian, uint32(0xDEADBEEF))
		require.NoError(t, err)

		output := &DropNotify{}
		err = output.Decode(buf.Bytes())
		require.NoError(t, err)

		require.Equal(t, uint32(0xDEADBEEF), binary.NativeEndian.Uint32(buf.Bytes()[output.DataOffset():]))
	}
}

func BenchmarkNewDropNotifyV1_Decode(b *testing.B) {
	input := DropNotify{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, binary.NativeEndian, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		dn := &DropNotify{}
		if err := dn.Decode(buf.Bytes()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOldDropNotifyV1_Decode(b *testing.B) {
	input := DropNotify{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, binary.NativeEndian, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		dn := &DropNotify{}
		if err := binary.Read(bytes.NewReader(buf.Bytes()), binary.NativeEndian, dn); err != nil {
			b.Fatal(err)
		}
	}
}
