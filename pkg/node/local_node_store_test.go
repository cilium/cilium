// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"golang.org/x/exp/slices"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	. "github.com/cilium/cilium/pkg/node"
)

type testInitializer struct{}

func (testInitializer) InitLocalNode(n *LocalNode) error {
	n.NodeIdentity = 1
	return nil
}

func TestLocalNodeStore(t *testing.T) {
	var waitObserve sync.WaitGroup
	var observed []uint32
	expected := []uint32{1, 2, 3, 4, 5}

	waitObserve.Add(1)

	// observe observes changes to the LocalNodeStore and completes
	// waitObserve after the last change has been observed.
	observe := func(store LocalNodeStore) {
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
	update := func(lc hive.Lifecycle, store LocalNodeStore) {
		lc.Append(hive.Hook{
			OnStart: func(hive.HookContext) error {
				// emit 2, 3, 4, 5
				for _, i := range expected[1:] {
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

		cell.Provide(func() LocalNodeInitializer { return testInitializer{} }),
		cell.Invoke(observe),
		cell.Invoke(update),
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if err := hive.Start(ctx); err != nil {
		t.Fatalf("Failed to start: %s", err)
	}

	// Wait until all values have been observed
	waitObserve.Wait()

	if err := hive.Stop(ctx); err != nil {
		t.Fatalf("Failed to stop: %s", err)
	}

	if !slices.Equal(observed, expected) {
		t.Fatalf("Unexpected values observed: %v, expected: %v", observed, expected)
	}
}
