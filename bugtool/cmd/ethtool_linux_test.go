// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package cmd

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFormatNICStats(t *testing.T) {
	stats := []struct {
		name  string
		value uint64
	}{
		{"rx_drops", 435},
		{"pps_allowance_exceeded", 7},
		{"conntrack_allowance_available", 1<<40 + 1},
	}
	names := make([]byte, 12+len(stats)*ethGStringLen)
	binary.NativeEndian.PutUint32(names[8:], uint32(len(stats)))
	values := make([]byte, 8+len(stats)*8)
	binary.NativeEndian.PutUint32(values[4:], uint32(len(stats)))
	for i, s := range stats {
		copy(names[12+i*ethGStringLen:], s.name)
		binary.NativeEndian.PutUint64(values[8+i*8:], s.value)
	}

	out, err := formatNICStats(names, values)
	require.NoError(t, err)
	require.Equal(t, "     rx_drops: 435\n     pps_allowance_exceeded: 7\n     conntrack_allowance_available: 1099511627777\n", out)

	_, err = formatNICStats(names[:20], values)
	require.Error(t, err)
}
