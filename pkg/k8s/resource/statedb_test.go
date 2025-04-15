// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/stream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/k8s/resource"
)

var (
	nodeNameIndex = statedb.Index[*corev1.Node, string]{
		Name: "name",
		FromObject: func(obj *corev1.Node) index.KeySet {
			return index.NewKeySet(index.String(obj.Name))
		},
		FromKey: index.String,
		Unique:  true,
	}
)

func newNodesTable(db *statedb.DB) (statedb.RWTable[*corev1.Node], error) {
	tbl, err := statedb.NewTable(
		"nodes",
		nodeNameIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}

func TestStateDBTableEventStream(t *testing.T) {
	db := statedb.New()
	nodes, err := newNodesTable(db)
	require.NoError(t, err)

	wtxn := db.WriteTxn(nodes)
	initDone := nodes.RegisterInitializer(wtxn, "test")
	wtxn.Commit()

	tableStream := resource.NewTableEventStream(
		db,
		nodes,
		func(k resource.Key) statedb.Query[*corev1.Node] {
			return nodeNameIndex.Query(k.String())
		},
	)

	// No sync event before initialized
	{
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		ev, ok := <-stream.ToChannel(ctx, tableStream)
		cancel()
		require.False(t, ok) // Channel should be closed
		require.Equal(t, resource.Event[*corev1.Node]{}, ev)
	}

	// Mark the table initialized, emitting the Sync event to observers.
	wtxn = db.WriteTxn(nodes)
	initDone(wtxn)
	wtxn.Commit()

	// Test that sync events are retried
	{
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		t.Cleanup(cancel)
		xs := stream.ToChannel(ctx, tableStream)

		expectedErr := errors.New("sync")
		expectedRetries := 3
		numRetries := 0

		for ev := range xs {
			switch ev.Kind {
			case resource.Sync:
				numRetries++
				if numRetries >= expectedRetries {
					ev.Done(nil)
					cancel()
				} else {
					ev.Done(expectedErr)
				}
			case resource.Upsert:
				t.Fatalf("unexpected upsert of %s", ev.Key)
			case resource.Delete:
				t.Fatalf("unexpected delete of %s", ev.Key)
			}
		}
		assert.Equal(t, expectedRetries, numRetries, "expected to see 3 retries for sync")
	}

	// Create the initial version of the node.
	var node = &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "some-node",
			ResourceVersion: "0",
		},
		Status: corev1.NodeStatus{
			Phase: "init",
		},
	}

	wtxn = db.WriteTxn(nodes)
	nodes.Insert(wtxn, node)
	wtxn.Commit()

	// Test that update events are retried
	{
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		t.Cleanup(cancel)
		xs := stream.ToChannel(ctx, tableStream)

		expectedErr := errors.New("update")
		expectedRetries := 3
		numRetries := 0

		for ev := range xs {
			switch ev.Kind {
			case resource.Sync:
				ev.Done(nil)
			case resource.Upsert:
				numRetries++
				if numRetries >= expectedRetries {
					ev.Done(nil)
					cancel()
				} else {
					ev.Done(expectedErr)
				}
			case resource.Delete:
				t.Fatalf("unexpected delete of %s", ev.Key)
			}
		}

		assert.Equal(t, expectedRetries, numRetries, "expected to see 3 retries for update")
	}

	// Test that delete events are retried
	{
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		t.Cleanup(cancel)
		xs := stream.ToChannel(ctx, tableStream)

		expectedErr := errors.New("delete")
		expectedRetries := 3
		numRetries := 0

		for ev := range xs {
			switch ev.Kind {
			case resource.Sync:
				ev.Done(nil)
			case resource.Upsert:
				wtxn := db.WriteTxn(nodes)
				nodes.Delete(wtxn, ev.Object)
				wtxn.Commit()
				ev.Done(nil)
			case resource.Delete:
				numRetries++
				if numRetries >= expectedRetries {
					ev.Done(nil)
					cancel()
				} else {
					ev.Done(expectedErr)
				}
			}
		}

		assert.Equal(t, expectedRetries, numRetries, "expected to see 3 retries for delete")
	}
}
