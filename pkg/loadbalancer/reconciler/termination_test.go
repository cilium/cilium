// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package reconciler

import (
	"context"
	"iter"
	"log/slog"
	"maps"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/cilium/cilium/pkg/datapath/sockets"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestSocketTermination(t *testing.T) {
	if testutils.IsPrivileged() {
		t.SkipNow()
	}

	var (
		db       *statedb.DB
		backends statedb.RWTable[*loadbalancer.Backend]
	)
	mock := &mockDestroyer{
		requests: make(chan sockets.SocketFilter, 10),
	}
	var beAddr loadbalancer.L3n4Addr
	require.NoError(t, beAddr.ParseFromString("1.0.0.1:80/UDP"))

	syncChan := make(testSyncChan)

	visitedNamespaces := []*netns.NetNS{}
	hostNS := &netns.NetNS{}
	fooNS := &netns.NetNS{}

	h := hive.New(
		maglev.Cell,
		lbmaps.Cell,

		cell.Provide(
			loadbalancer.NewBackendsTable,
			statedb.RWTable[*loadbalancer.Backend].ToTable,
			func() sockets.SocketDestroyer { return mock },
			func() loadbalancer.Config {
				return loadbalancer.Config{
					EnableExperimentalLB: true,
					RetryBackoffMin:      0,
					RetryBackoffMax:      0,
				}
			},
			func() loadbalancer.ExternalConfig {
				return loadbalancer.ExternalConfig{
					BPFSocketLBHostnsOnly:                  false,
					EnableSocketLB:                         true,
					EnableSocketLBPodConnectionTermination: true,
					LBMapsConfig:                           loadbalancer.LBMapsConfig{},
					EnableIPv4:                             true,
					EnableIPv6:                             true,
				}

			},
			func() *loadbalancer.TestConfig { return &loadbalancer.TestConfig{} },
			func() testSyncChan { return syncChan },
			func() netnsOps {
				return netnsOps{
					current: func() (*netns.NetNS, error) {
						return hostNS, nil
					},
					do: func(ns *netns.NetNS, f func() error) error {
						visitedNamespaces = append(visitedNamespaces, ns)
						return f()
					},
					all: func() (iter.Seq2[string, *netns.NetNS], <-chan error) {
						errs := make(chan error)
						close(errs)
						return maps.All(map[string]*netns.NetNS{
							"foo": fooNS,
						}), errs
					},
				}
			},
		),
		cell.Module("test", "test",
			cell.Invoke(registerSocketTermination),
		),
		cell.Invoke(func(db_ *statedb.DB, backends_ statedb.RWTable[*loadbalancer.Backend]) {
			db = db_
			backends = backends_

		}),
	)
	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	require.NoError(t, h.Start(log, t.Context()), "Start")
	t.Cleanup(func() {
		require.NoError(t, h.Stop(log, context.Background()), "Stop")
		goleak.VerifyNone(t)
	})

	// Add a backends and wait for the job to pick it up
	wtxn := db.WriteTxn(backends)
	backends.Insert(wtxn, &loadbalancer.Backend{Address: beAddr})
	wtxn.Commit()

	// Wait until the first change has been seen
	<-syncChan

	wtxn = db.WriteTxn(backends)
	backends.DeleteAll(wtxn)
	wtxn.Commit()

	// We should see two deletions: one for host ns and one for the mocked
	// "foo" one.

	filter := <-mock.requests
	require.True(t, beAddr.AddrCluster.AsNetIP().Equal(filter.DestIp), "IP matches")
	require.Equal(t, beAddr.Port, filter.DestPort, "Port matches")

	filter = <-mock.requests
	require.True(t, beAddr.AddrCluster.AsNetIP().Equal(filter.DestIp), "IP matches")
	require.Equal(t, beAddr.Port, filter.DestPort, "Port matches")

	require.ElementsMatch(t, visitedNamespaces, []*netns.NetNS{hostNS, fooNS})
}

type mockDestroyer struct {
	requests chan sockets.SocketFilter
}

// Destroy implements sockets.SocketDestroyer.
func (m *mockDestroyer) Destroy(filter sockets.SocketFilter) error {
	m.requests <- filter
	return nil
}

var _ sockets.SocketDestroyer = &mockDestroyer{}
