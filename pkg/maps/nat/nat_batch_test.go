// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nat

import (
	"testing"

	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"

	"github.com/stretchr/testify/assert"
)

func TestDumpBatch4(t *testing.T) {
	testutils.PrivilegedTest(t)
	m := NewMap("test_snat_map", IPv4, 1<<18) // approximate default map size.
	m.family = IPv4
	err := m.OpenOrCreate()
	assert.NoError(t, err)
	defer assert.NoError(t, m.UnpinIfExists())
	for i := 0; i < 1024+1; i++ {
		var ip types.IPv4
		ip[0] = byte(i)
		ip[1] = byte(i >> 8)
		ip[2] = byte(i >> 16)
		ip[3] = byte(i >> 24)

		mapKey := &NatKey4{}
		mapKey.TupleKey4.DestAddr = ip
		mapKey.TupleKey4.DestPort = uint16(i)
		mapKey.Flags = tuple.TUPLE_F_IN
		mapValue := &NatEntry4{}
		err := m.Update(mapKey, mapValue)
		assert.NoError(t, err)
	}
	count, err := m.DumpBatch4(func(tk *tuple.TupleKey4, ne *NatEntry4) {})
	assert.NoError(t, err)
	assert.Equal(t, 1024+1, count)
}
