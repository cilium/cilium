// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/statedb"
)

type mockSyncNodePort struct {
	lock.Mutex
	errToReturn error
	addrs       sets.Set[netip.Addr]
	success     bool
}

// SyncNodePortFrontends implements syncNodePort.
func (m *mockSyncNodePort) SyncNodePortFrontends(addrs sets.Set[netip.Addr]) error {
	m.Lock()
	defer m.Unlock()
	m.addrs = addrs
	m.success = m.errToReturn == nil
	return m.errToReturn
}

var _ syncNodePort = &mockSyncNodePort{}

func TestServiceReconciler(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	mock := &mockSyncNodePort{
		errToReturn: nil,
		addrs:       nil,
	}
	var (
		db        *statedb.DB
		nodeAddrs statedb.RWTable[tables.NodeAddress]
	)

	h := hive.New(
		job.Cell,
		statedb.Cell,
		cell.Module("test", "test",
			cell.Provide(
				tables.NewNodeAddressTable,
				statedb.RWTable[tables.NodeAddress].ToTable,
			),
			cell.Invoke(statedb.RegisterTable[tables.NodeAddress]),
			cell.Provide(func() syncNodePort { return mock }),
			cell.Invoke(registerServiceReconciler),
			cell.Invoke(func(d *statedb.DB, na statedb.RWTable[tables.NodeAddress]) {
				db = d
				nodeAddrs = na
			}),
		),
	)

	require.NoError(t, h.Start(context.TODO()), "Start")

	mock.Lock()
	mock.errToReturn = errors.New("fail")
	mock.Unlock()

	wtxn := db.WriteTxn(nodeAddrs)
	nodeAddrs.Insert(
		wtxn,
		tables.NodeAddress{
			Addr:       netip.MustParseAddr("1.2.3.4"),
			NodePort:   true,
			Primary:    true,
			DeviceName: "test",
		},
	)
	wtxn.Commit()

	require.Eventually(t,
		func() bool {
			mock.Lock()
			defer mock.Unlock()
			return len(mock.addrs) == 1 && !mock.success
		}, time.Second, 10*time.Millisecond)

	mock.Lock()
	mock.errToReturn = nil
	mock.Unlock()

	require.Eventually(t,
		func() bool {
			mock.Lock()
			defer mock.Unlock()
			return mock.success
		}, time.Second, 10*time.Millisecond)

	require.NoError(t, h.Stop(context.TODO()), "Stop")

}
