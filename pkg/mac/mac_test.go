// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mac

import (
	"encoding/json"
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
			nil,
			"invalid MAC address",
		},
		// not IEEE 802 MAC-48
		{
			"00:00:00:00:fe:80:00:00:00:00:00:00:02:00:5e:10:00:00:00:01",
			nil,
			"invalid MAC address",
		},
		{
			"00-00-00-00-fe-80-00-00-00-00-00-00-02-00-5e-10-00-00-00-01",
			nil,
			"invalid MAC address",
		},
		{
			"0000.0000.fe80.0000.0000.0000.0200.5e10.0000.0001",
			nil,
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

func TestUint64(t *testing.T) {
	m := MAC([]byte{0x11, 0x12, 0x23, 0x34, 0x45, 0x56})
	v, err := m.Uint64()
	require.NoError(t, err)
	require.Equal(t, Uint64MAC(0x564534231211), v)
}

func TestUnmarshalYAML(t *testing.T) {
	m := MustParseMAC("11:12:23:34:45:56")
	w := MAC([]byte{0x11, 0x12, 0x23, 0x34, 0x45, 0xAB})
	d, err := yaml.Marshal(m)
	require.NoError(t, err)
	require.Equal(t, []byte("\"11:12:23:34:45:56\"\n"), d)
	var t1 MAC
	err = yaml.Unmarshal([]byte("11:12:23:34:45:AB"), &t1)
	require.NoError(t, err)
	require.Equal(t, w, t1)
	err = yaml.Unmarshal([]byte("11:12:23:34:45:A"), &t1)
	require.Error(t, err)

	m = MAC([]byte{})
	w = MAC([]byte{})
	d, err = yaml.Marshal(m)
	require.NoError(t, err)
	require.Equal(t, []byte("\"\"\n"), d)
	var t2 MAC
	err = yaml.Unmarshal([]byte(`""`), &t2)
	require.NoError(t, err)
	require.Equal(t, w, t2)
}

func TestUnmarshalJSON(t *testing.T) {
	m := MAC([]byte{0x11, 0x12, 0x23, 0x34, 0x45, 0x56})
	w := MAC([]byte{0x11, 0x12, 0x23, 0x34, 0x45, 0xAB})
	d, err := json.Marshal(m)
	require.NoError(t, err)
	require.Equal(t, []byte(`"11:12:23:34:45:56"`), d)
	var t1 MAC
	err = json.Unmarshal([]byte(`"11:12:23:34:45:AB"`), &t1)
	require.NoError(t, err)
	require.Equal(t, w, t1)
	err = json.Unmarshal([]byte(`"11:12:23:34:45:A"`), &t1)
	require.Error(t, err)

	m = MAC([]byte{})
	w = MAC([]byte{})
	d, err = json.Marshal(m)
	require.NoError(t, err)
	require.Equal(t, []byte(`""`), d)
	var t2 MAC
	err = json.Unmarshal([]byte(`""`), &t2)
	require.NoError(t, err)
	require.Equal(t, w, t2)
}
