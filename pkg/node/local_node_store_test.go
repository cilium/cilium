// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node_test

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/hive"
	. "github.com/cilium/cilium/pkg/node"
)

type testSynchronizer struct{ identity chan uint32 }

func (testSynchronizer) InitLocalNode(ctx context.Context, n *LocalNode) error {
	n.NodeIdentity = 1
	return nil
}

func (ts testSynchronizer) SyncLocalNode(ctx context.Context, lns *LocalNodeStore) {
	id := <-ts.identity
	lns.Update(func(n *LocalNode) { n.NodeIdentity = id })
	<-ctx.Done()
}

func TestLocalNodeStore(t *testing.T) {
	var waitObserve sync.WaitGroup
	var observed []uint32
	expected := []uint32{1, 2, 3, 4, 5}

	waitObserve.Add(1)

	ts := testSynchronizer{identity: make(chan uint32, 1)}

	// observe observes changes to the LocalNodeStore and completes
	// waitObserve after the last change has been observed.
	observe := func(store *LocalNodeStore) {
		store.Observe(context.TODO(),
			func(n LocalNode) {
				observed = append(observed, n.NodeIdentity)

				if n.NodeIdentity == expected[len(expected)-1] {
					waitObserve.Done()
				}
			},
			func(err error) {},
		)
	}

	// update adds a start hook to the application that modifies
	// the local node.
	update := func(lc cell.Lifecycle, store *LocalNodeStore) {
		lc.Append(cell.Hook{
			OnStart: func(cell.HookContext) error {
				// emit 2, 3, 4, 5
				for _, i := range expected[1:] {
					if i == 5 {
						ts.identity <- i
						continue
					}

					store.Update(func(n *LocalNode) {
						n.NodeIdentity = i
					})
				}
				return nil
			},
		})
	}

	hive := hive.New(
		cell.Provide(NewLocalNodeStore),

		cell.Provide(func() LocalNodeSynchronizer { return ts }),
		cell.Invoke(observe),
		cell.Invoke(update),
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, ctx); err != nil {
		t.Fatalf("Failed to start: %s", err)
	}

	// Wait until all values have been observed
	waitObserve.Wait()

	if err := hive.Stop(tlog, ctx); err != nil {
		t.Fatalf("Failed to stop: %s", err)
	}

	if !slices.Equal(observed, expected) {
		t.Fatalf("Unexpected values observed: %v, expected: %v", observed, expected)
	}
}

func BenchmarkLocalNodeStoreGet(b *testing.B) {
	ctx := context.Background()
	lns := NewTestLocalNodeStore(LocalNode{})

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = lns.Get(ctx)
	}
}
