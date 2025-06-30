// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package neighbor

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
)

func TestForwardableIPManager(t *testing.T) {
	var (
		fim *ForwardableIPManager
		fip statedb.Table[*ForwardableIP]
		db  *statedb.DB
	)

	h := hive.New(
		ForwardableIPCell,
		cell.Provide(NewCommonTestConfig(true, false)),
		cell.Invoke(func(
			fim_ *ForwardableIPManager,
			fip_ statedb.Table[*ForwardableIP],
			db_ *statedb.DB,
		) {
			fim = fim_
			fip = fip_
			db = db_
		}),
	)

	err := h.Populate(hivetest.Logger(t))
	require.NoError(t, err, "Failed to run hive")

	nodeOwner := ForwardableIPOwner{
		Type: ForwardableIPOwnerNode,
		ID:   "node1",
	}
	serviceOwner := ForwardableIPOwner{
		Type: ForwardableIPOwnerService,
		ID:   "svc1",
	}
	ip1 := netip.MustParseAddr("10.0.0.1")
	ip2 := netip.MustParseAddr("20.0.0.2")

	// Insert ip1:nodeowner and ip2:serviceOwner
	// We expect to see these in the table
	err = fim.Insert(ip1, nodeOwner)
	require.NoError(t, err)
	err = fim.Insert(ip2, serviceOwner)
	require.NoError(t, err)

	fis := statedb.Collect(fip.All(db.ReadTxn()))
	require.ElementsMatch(t, fis, []*ForwardableIP{
		{
			IP:     ip1,
			Owners: []ForwardableIPOwner{nodeOwner},
		},
		{
			IP:     ip2,
			Owners: []ForwardableIPOwner{serviceOwner},
		},
	})

	// Delete ip2:serviceOwner, should remove it from the table
	err = fim.Delete(ip2, serviceOwner)
	require.NoError(t, err)
	fis = statedb.Collect(fip.All(db.ReadTxn()))
	require.ElementsMatch(t, fis, []*ForwardableIP{
		{
			IP:     ip1,
			Owners: []ForwardableIPOwner{nodeOwner},
		},
	})

	// Insert ip1:nodeOwner, which already exists, should not modify the table
	err = fim.Insert(ip1, nodeOwner)
	require.NoError(t, err)
	fis = statedb.Collect(fip.All(db.ReadTxn()))
	require.ElementsMatch(t, fis, []*ForwardableIP{
		{
			IP:     ip1,
			Owners: []ForwardableIPOwner{nodeOwner},
		},
	})

	// Insert ip1:serviceOwner, should add the service owner to the existing entry
	err = fim.Insert(ip1, serviceOwner)
	require.NoError(t, err)
	fis = statedb.Collect(fip.All(db.ReadTxn()))
	require.ElementsMatch(t, fis, []*ForwardableIP{
		{
			IP:     ip1,
			Owners: []ForwardableIPOwner{nodeOwner, serviceOwner},
		},
	})

	// Delete ip1:nodeOwner, should remove the node owner from the existing entry
	// but keep the entry in the table
	err = fim.Delete(ip1, nodeOwner)
	require.NoError(t, err)
	fis = statedb.Collect(fip.All(db.ReadTxn()))
	require.ElementsMatch(t, fis, []*ForwardableIP{
		{
			IP:     ip1,
			Owners: []ForwardableIPOwner{serviceOwner},
		},
	})
}
