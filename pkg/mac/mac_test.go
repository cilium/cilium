// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mac

import (
	"encoding/json"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestParse(t *testing.T) {
	macTests := []struct {
		in      string
		out     MAC
		wantErr string
	}{
		{"00:00:5e:00:53:01", MAC{0x00, 0x00, 0x5e, 0x00, 0x53, 0x01}, ""},
		{"00-00-5e-00-53-01", MAC{0x00, 0x00, 0x5e, 0x00, 0x53, 0x01}, ""},
		{"0000.5e00.5301", MAC{0x00, 0x00, 0x5e, 0x00, 0x53, 0x01}, ""},

		// invalid delimiter
		{
			"01.02.03.04.05.06",
			MAC{},
			"invalid MAC address",
		},
		// not IEEE 802 MAC-48
		{
			"00:00:00:00:fe:80:00:00:00:00:00:00:02:00:5e:10:00:00:00:01",
			MAC{},
			"invalid MAC address",
		},
		{
			"00-00-00-00-fe-80-00-00-00-00-00-00-02-00-5e-10-00-00-00-01",
			MAC{},
			"invalid MAC address",
		},
		{
			"0000.0000.fe80.0000.0000.0000.0200.5e10.0000.0001",
			MAC{},
			"invalid MAC address",
		},
	}

	for _, tt := range macTests {
		t.Run(tt.in, func(t *testing.T) {
			out, err := ParseMAC(tt.in)
			require.Equal(t, tt.out, out)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.wantErr)
				require.Panics(t, func() { _ = MustParseMAC(tt.in) })
			}
		})
	}
}

func TestIsValid(t *testing.T) {
	tests := []struct {
		name  string
		in    MAC
		valid bool
	}{
		{"zero value", MAC{}, false},
		{"mac-48", MAC{0x11, 0x12, 0x23, 0x34, 0x45, 0x56}, true},
		// The zero value is the "unset" sentinel, so the all-zero MAC-48 is not
		// representable as a distinct address.
		{"all-zero mac-48", MustParseMAC("00:00:00:00:00:00"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.valid, tt.in.IsValid())
		})
	}
}

func TestFromHardwareAddr(t *testing.T) {
	tests := []struct {
		name    string
		in      net.HardwareAddr
		out     MAC
		wantErr bool
	}{
		{"mac-48", net.HardwareAddr{0x11, 0x12, 0x23, 0x34, 0x45, 0x56}, MAC{0x11, 0x12, 0x23, 0x34, 0x45, 0x56}, false},
		// An L3/NOARP device reports no hardware address at all.
		{"nil", nil, MAC{}, true},
		{"empty", net.HardwareAddr{}, MAC{}, true},
		{"too short", net.HardwareAddr{0x11, 0x12, 0x23}, MAC{}, true},
		// Not IEEE 802 MAC-48, unlike [net.ParseMAC] which accepts EUI-64.
		{"eui-64", net.HardwareAddr{0x11, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78}, MAC{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := FromHardwareAddr(tt.in)
			require.Equal(t, tt.out, out)
			if tt.wantErr {
				require.ErrorContains(t, err, "invalid MAC address")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestStringUnset asserts that an unset MAC has no text representation, and
// that [MAC.String] and [MAC.MarshalText] agree on it. Both are relied upon to
// keep an unset MAC off the wire as "" rather than "00:00:00:00:00:00".
func TestStringUnset(t *testing.T) {
	require.Empty(t, MAC{}.String())

	text, err := MAC{}.MarshalText()
	require.NoError(t, err)
	require.Empty(t, text)

	var m MAC
	require.NoError(t, m.UnmarshalText(text))
	require.Equal(t, MAC{}, m)
}

func TestHardwareAddr(t *testing.T) {
	m := MAC{0x11, 0x12, 0x23, 0x34, 0x45, 0x56}
	ha := m.HardwareAddr()
	require.Equal(t, net.HardwareAddr{0x11, 0x12, 0x23, 0x34, 0x45, 0x56}, ha)

	// The result is a copy: mutating it must not affect m.
	ha[0] = 0xff
	require.Equal(t, MAC{0x11, 0x12, 0x23, 0x34, 0x45, 0x56}, m)

	// An unset MAC maps to a nil net.HardwareAddr, not to six zero bytes, so
	// that netlink leaves the address attribute out entirely.
	require.Nil(t, MAC{}.HardwareAddr())
}

func TestUnmarshalYAML(t *testing.T) {
	m := MustParseMAC("11:12:23:34:45:56")
	w := MAC{0x11, 0x12, 0x23, 0x34, 0x45, 0xAB}
	d, err := yaml.Marshal(m)
	require.NoError(t, err)
	require.Equal(t, []byte("\"11:12:23:34:45:56\"\n"), d)
	var t1 MAC
	err = yaml.Unmarshal([]byte("11:12:23:34:45:AB"), &t1)
	require.NoError(t, err)
	require.Equal(t, w, t1)
	err = yaml.Unmarshal([]byte("11:12:23:34:45:A"), &t1)
	require.Error(t, err)

	m = MAC{}
	w = MAC{}
	d, err = yaml.Marshal(m)
	require.NoError(t, err)
	require.Equal(t, []byte("\"\"\n"), d)
	var t2 MAC
	err = yaml.Unmarshal([]byte(`""`), &t2)
	require.NoError(t, err)
	require.Equal(t, w, t2)
}

func TestUnmarshalJSON(t *testing.T) {
	m := MAC{0x11, 0x12, 0x23, 0x34, 0x45, 0x56}
	w := MAC{0x11, 0x12, 0x23, 0x34, 0x45, 0xAB}
	d, err := json.Marshal(m)
	require.NoError(t, err)
	require.Equal(t, []byte(`"11:12:23:34:45:56"`), d)
	var t1 MAC
	err = json.Unmarshal([]byte(`"11:12:23:34:45:AB"`), &t1)
	require.NoError(t, err)
	require.Equal(t, w, t1)
	err = json.Unmarshal([]byte(`"11:12:23:34:45:A"`), &t1)
	require.Error(t, err)

	m = MAC{}
	w = MAC{}
	d, err = json.Marshal(m)
	require.NoError(t, err)
	require.Equal(t, []byte(`""`), d)
	var t2 MAC
	err = json.Unmarshal([]byte(`""`), &t2)
	require.NoError(t, err)
	require.Equal(t, w, t2)
}

// TestOmitZero asserts that a zero MAC is omitted by encoding/json's omitzero
// tag option, which the generated API models rely on to reproduce the wire
// format the slice-backed MAC produced with omitempty.
func TestOmitZero(t *testing.T) {
	type model struct {
		Mac MAC `json:"mac,omitempty,omitzero"`
	}

	d, err := json.Marshal(model{})
	require.NoError(t, err)
	require.JSONEq(t, `{}`, string(d))

	d, err = json.Marshal(model{Mac: MustParseMAC("11:12:23:34:45:56")})
	require.NoError(t, err)
	require.JSONEq(t, `{"mac":"11:12:23:34:45:56"}`, string(d))
}
