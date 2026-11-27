// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resolver

import (
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/tables"
)

func TestLinkGetter(t *testing.T) {
	db := statedb.New()
	devices, err := tables.NewDeviceTable(db)
	require.NoError(t, err)

	txn := db.WriteTxn(devices)
	devices.Insert(txn, &tables.Device{Index: 1, Name: "eth0", Selected: true})
	devices.Insert(txn, &tables.Device{Index: 2, Name: "lxc0", Selected: false})
	// Seen only through address or route updates.
	devices.Insert(txn, &tables.Device{Index: 3})
	txn.Commit()

	g := NewLinkGetter(db, devices)

	for _, tc := range []struct {
		name    string
		ifIndex int
		want    string
		found   bool
	}{
		{"selected", 1, "eth0", true},
		{"unselected", 2, "lxc0", true},
		{"unnamed", 3, "", false},
		{"unknown", 4, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name, found := g.GetIfNameCached(tc.ifIndex)
			assert.Equal(t, tc.want, name)
			assert.Equal(t, tc.found, found)
		})
	}
	assert.Equal(t, "eth0", g.Name(1))
	assert.Equal(t, "3", g.Name(3))

	txn = db.WriteTxn(devices)
	devices.Delete(txn, &tables.Device{Index: 1})
	txn.Commit()

	_, found := g.GetIfNameCached(1)
	assert.False(t, found)
	assert.Equal(t, "1", g.Name(1))
}
