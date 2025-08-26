// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mac

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUint64(t *testing.T) {
	m := MAC([]byte{0x11, 0x12, 0x23, 0x34, 0x45, 0x56})
	v, err := m.Uint64()
	require.NoError(t, err)
	require.Equal(t, Uint64MAC(0x564534231211), v)
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
