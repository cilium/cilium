// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bandwidth

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func TestPrivilegedOps(t *testing.T) {
	testutils.PrivilegedTest(t)
	log := hivetest.Logger(t)

	var nlh *netlink.Handle
	var err error

	ns := netns.NewNetNS(t)
	require.NoError(t, ns.Do(func() error {
		nlh, err = safenetlink.NewHandle(nil)
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
	link, err := safenetlink.WithRetryResult(func() (netlink.Link, error) {
		//nolint:forbidigo
		return nlh.LinkByName("dummy0")
	})
	require.NoError(t, err, "LinkByName")
	require.NoError(t, nlh.LinkSetUp(link))
	index := link.Attrs().Index
	name := link.Attrs().Name

	t.Logf("created %s (index %d)", name, index)

	// Check that the default qdisc is
	qdiscs, err := safenetlink.WithRetryResult(func() ([]netlink.Qdisc, error) {
		//nolint:forbidigo
		return nlh.QdiscList(link)
	})
	require.NoError(t, err, "QdiscList")
	require.Len(t, qdiscs, 1)
	t.Logf("qdiscs before: %+v", qdiscs)
	require.Equal(t, "noqueue", qdiscs[0].Type()) // the default for dummys

	ops := &ops{
		log:       log,
		isEnabled: func() bool { return true },
		devices:   nil, // not accessed for non-bond devices
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
	qdiscs, err = safenetlink.WithRetryResult(func() ([]netlink.Qdisc, error) {
		//nolint:forbidigo
		return nlh.QdiscList(link)
	})
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

func TestPrivilegedOpsBond(t *testing.T) {
	testutils.PrivilegedTest(t)
	log := hivetest.Logger(t)

	var bondIndex int
	var slaveIndices = map[string]int{}
	var err error

	ns := netns.NewNetNS(t)
	var slaveAssignErr error
	require.NoError(t, ns.Do(func() error {
		if err := netlink.LinkAdd(netlink.NewLinkBond(netlink.LinkAttrs{Name: "bond0"})); err != nil {
			return fmt.Errorf("LinkAdd bond0: %w", err)
		}
		bond, err := safenetlink.LinkByName("bond0")
		if err != nil {
			return fmt.Errorf("LinkByName bond0: %w", err)
		}
		bondIndex = bond.Attrs().Index
		if err := netlink.LinkSetUp(bond); err != nil {
			return fmt.Errorf("LinkSetUp bond0: %w", err)
		}
		for _, name := range []string{"slave0", "slave1"} {
			if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
				return fmt.Errorf("LinkAdd %s: %w", name, err)
			}
			slave, err := safenetlink.LinkByName(name)
			if err != nil {
				return fmt.Errorf("LinkByName %s: %w", name, err)
			}
			if err := netlink.LinkSetUp(slave); err != nil {
				return fmt.Errorf("LinkSetUp %s: %w", name, err)
			}
			if e := netlink.LinkSetMasterByIndex(slave, bondIndex); e != nil {
				slaveAssignErr = fmt.Errorf("LinkSetMasterByIndex %s: %w", name, e)
				return nil
			}
			slaveIndices[name] = slave.Attrs().Index
		}
		return nil
	}), "bond/slave setup in netns")
	if slaveAssignErr != nil {
		t.Skipf("skipping: cannot assign bond slaves on this kernel (%v)", slaveAssignErr)
	}

	// Populate the device table with the bond slave devices.
	db := statedb.New()
	deviceTable, err := tables.NewDeviceTable(db)
	require.NoError(t, err, "NewDeviceTable")
	wtxn := db.WriteTxn(deviceTable)
	for name, idx := range slaveIndices {
		deviceTable.Insert(wtxn, &tables.Device{
			Index:       idx,
			Name:        name,
			MasterIndex: bondIndex,
		})
	}
	wtxn.Commit()

	ops := &ops{
		log:       log,
		isEnabled: func() bool { return true },
		devices:   deviceTable,
	}
	ctx := context.TODO()
	rtxn := db.ReadTxn()

	err = ns.Do(func() error {
		return ops.Update(ctx, rtxn, 0, &tables.BandwidthQDisc{
			LinkIndex: bondIndex,
			LinkName:  "bond0",
			FqHorizon: FqDefaultHorizon,
			FqBuckets: FqDefaultBuckets,
			Status:    reconciler.StatusPending(),
		})
	})
	require.NoError(t, err, "Update bond master")

	var bondQdiscs []netlink.Qdisc
	err = ns.Do(func() error {
		var e error
		bondMaster, e2 := netlink.LinkByIndex(bondIndex)
		if e2 != nil {
			return e2
		}
		bondQdiscs, e = safenetlink.QdiscList(bondMaster)
		return e
	})
	require.NoError(t, err, "QdiscList bond master")
	t.Logf("bond master qdiscs: %+v", bondQdiscs)
	require.Len(t, bondQdiscs, 1)
	require.Equal(t, "noqueue", bondQdiscs[0].Type(), "bond master should have noqueue")

	for _, slaveName := range []string{"slave0", "slave1"} {
		var slaveQdiscs []netlink.Qdisc
		err = ns.Do(func() error {
			slave, e := safenetlink.LinkByName(slaveName)
			if e != nil {
				return e
			}
			var e2 error
			slaveQdiscs, e2 = safenetlink.QdiscList(slave)
			return e2
		})
		require.NoError(t, err, "QdiscList", slaveName)
		t.Logf("slave %s qdiscs: %+v", slaveName, slaveQdiscs)

		require.NotEmpty(t, slaveQdiscs, "slave %s should have qdiscs", slaveName)
		rootType := slaveQdiscs[0].Type()
		require.True(t, rootType == "mq" || rootType == "fq",
			"slave %s root qdisc should be mq or fq, got %s", slaveName, rootType)
	}

	err = ns.Do(func() error {
		return ops.Update(ctx, rtxn, 0, &tables.BandwidthQDisc{
			LinkIndex: bondIndex,
			LinkName:  "bond0",
			FqHorizon: FqDefaultHorizon,
			FqBuckets: FqDefaultBuckets,
			Status:    reconciler.StatusPending(),
		})
	})
	require.NoError(t, err, "second Update bond master should be idempotent")
}

func TestPrivilegedOpsBondNoSlaves(t *testing.T) {
	testutils.PrivilegedTest(t)
	log := hivetest.Logger(t)

	var nlh *netlink.Handle
	var err error

	ns := netns.NewNetNS(t)
	require.NoError(t, ns.Do(func() error {
		nlh, err = safenetlink.NewHandle(nil)
		return err
	}))

	err = nlh.LinkAdd(netlink.NewLinkBond(netlink.LinkAttrs{Name: "bond0"}))
	require.NoError(t, err, "LinkAdd bond0")

	bondLink, err := safenetlink.WithRetryResult(func() (netlink.Link, error) {
		//nolint:forbidigo
		return nlh.LinkByName("bond0")
	})
	require.NoError(t, err, "LinkByName bond0")
	require.NoError(t, nlh.LinkSetUp(bondLink))

	// Empty device table — no slaves registered.
	db := statedb.New()
	deviceTable, err := tables.NewDeviceTable(db)
	require.NoError(t, err, "NewDeviceTable")

	ops := &ops{
		log:       log,
		isEnabled: func() bool { return true },
		devices:   deviceTable,
	}
	ctx := context.TODO()
	rtxn := db.ReadTxn()

	err = ns.Do(func() error {
		return ops.Update(ctx, rtxn, 0, &tables.BandwidthQDisc{
			LinkIndex: bondLink.Attrs().Index,
			LinkName:  bondLink.Attrs().Name,
			FqHorizon: FqDefaultHorizon,
			FqBuckets: FqDefaultBuckets,
			Status:    reconciler.StatusPending(),
		})
	})
	require.NoError(t, err, "Update bond with no slaves should succeed")
}
