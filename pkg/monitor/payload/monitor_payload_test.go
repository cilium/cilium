// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package payload

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMeta_UnMarshalBinary(t *testing.T) {
	meta1 := Meta{Size: 1234}
	buf, err := meta1.MarshalBinary()
	require.NoError(t, err)

	var meta2 Meta
	err = meta2.UnmarshalBinary(buf)
	require.NoError(t, err)

	require.Equal(t, meta2, meta1)
}

func TestPayload_UnMarshalBinary(t *testing.T) {
	payload1 := Payload{
		Data: []byte{1, 2, 3, 4},
		Lost: 5243,
		CPU:  12,
		Type: 9,
	}
	buf, err := payload1.Encode()
	require.NoError(t, err)

	var payload2 Payload
	err = payload2.Decode(buf)
	require.NoError(t, err)

	require.Equal(t, payload2, payload1)
}
