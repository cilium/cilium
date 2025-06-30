// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bandwidth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func TestOps(t *testing.T) {
	testutils.PrivilegedTest(t)
	log := hivetest.Logger(t)

	var nlh *netlink.Handle
	var err error

	ns := netns.NewNetNS(t)
	require.NoError(t, ns.Do(func() error {
		nlh, err = netlink.NewHandle()
		return err
	}))

	// Create a dummy device to test with
	err = nlh.LinkAdd(
		&netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: "dummy0",
			},
		},
	)
	require.NoError(t, err, "LinkAdd")
	link, err := nlh.LinkByName("dummy0")
	require.NoError(t, err, "LinkByName")
	require.NoError(t, nlh.LinkSetUp(link))
	index := link.Attrs().Index
	name := link.Attrs().Name

	t.Logf("created %s (index %d)", name, index)

	// Check that the default qdisc is
	qdiscs, err := nlh.QdiscList(link)
	require.NoError(t, err, "QdiscList")
	require.Len(t, qdiscs, 1)
	t.Logf("qdiscs before: %+v", qdiscs)
	require.Equal(t, "noqueue", qdiscs[0].Type()) // the default for dummys

	ops := &ops{
		log:       log,
		isEnabled: func() bool { return true },
	}
	ctx := context.TODO()

	// Initial Update()
	err = ns.Do(func() error {
		return ops.Update(ctx, nil, 0, &tables.BandwidthQDisc{
			LinkIndex: index,
			LinkName:  name,
			FqHorizon: FqDefaultHorizon,
			FqBuckets: FqDefaultBuckets,
			Status:    reconciler.StatusPending(),
		})
	})
	require.NoError(t, err, "expected no error from initial update")

	// qdisc should now have changed from "noqueue" to mq (or fq if mq not supported)
	qdiscs, err = nlh.QdiscList(link)
	require.NoError(t, err, "QdiscList")
	require.NotEmpty(t, qdiscs)
	t.Logf("qdiscs after: %+v", qdiscs)

	if qdiscs[0].Type() != "mq" {
		require.Equal(t, "fq", qdiscs[0].Type())
	} else {
		require.Equal(t, "mq", qdiscs[0].Type())
	}

	// Second Update() should not do anything.
	err = ns.Do(func() error {
		return ops.Update(ctx, nil, 0, &tables.BandwidthQDisc{
			LinkIndex: index,
			LinkName:  name,
			FqHorizon: FqDefaultHorizon,
			FqBuckets: FqDefaultBuckets,
			Status:    reconciler.StatusPending(),
		})
	})
	require.NoError(t, err, "expected no error from second update")

	// Non-existing devices return an error.
	err = ns.Do(func() error {
		return ops.Update(ctx, nil, 0, &tables.BandwidthQDisc{
			LinkIndex: 1234,
			LinkName:  name,
			FqHorizon: FqDefaultHorizon,
			FqBuckets: FqDefaultBuckets,
			Status:    reconciler.StatusPending(),
		})
	})
	require.Error(t, err, "expected no error from update of non-existing device")
}
