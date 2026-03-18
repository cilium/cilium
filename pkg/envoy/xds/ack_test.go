// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	node0 = "10.0.0.0"
	node1 = "10.0.0.1"
	node2 = "10.0.0.2"

	MaxCompletionDuration      = 100 * time.Millisecond
	CompletionAssertionTimeout = 1 * time.Second
)

type compCheck struct {
	err error
	ch  chan error
}

func newCompCheck() *compCheck {
	return &compCheck{
		ch: make(chan error, 1),
	}
}

func (c *compCheck) Err() error {
	return c.err
}

// Return a new completion callback that will write the completion error to a channel
func newCompCallback() (func(error), *compCheck) {
	comp := newCompCheck()
	callback := func(err error) {
		log.WithError(err).Debug("callback called")
		comp.ch <- err
		close(comp.ch)
	}
	return callback, comp
}

func completedComparison(comp *compCheck) assert.Comparison {
	return func() bool {
		return completedWithin(comp, CompletionAssertionTimeout)
	}
}

func isNotCompletedComparison(comp *compCheck) assert.Comparison {
	return func() bool {
		return !completedWithin(comp, 0)
	}
}

func doesNotCompleteComparison(comp *compCheck) assert.Comparison {
	return func() bool {
		return !completedWithin(comp, MaxCompletionDuration)
	}
}

func completedWithin(comp *compCheck, wait time.Duration) bool {
	if comp == nil {
		return false
	}

	if comp.err != nil {
		return false
	}

	if wait <= 0 {
		select {
		case comp.err = <-comp.ch:
			return comp.err == nil
		default:
			return false
		}
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case comp.err = <-comp.ch:
		return comp.err == nil
	case <-timer.C:
		return false
	}
}

func (m *AckingResourceMutatorWrapper) currentVersionAcked(nodeIDs []string) bool {
	for _, node := range nodeIDs {
		if acked, exists := m.ackedVersions[node]; !exists || acked < m.version {
			log.WithFields(logrus.Fields{
				logfields.XDSCachedVersion: m.version,
				logfields.XDSAckedVersion:  acked,
				logfields.XDSClientNode:    node,
			}).Debug("Node has not acked the current cached version yet")
			return false
		}
	}
	return true
}

func TestUpsertSingleNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"
	wg := completion.NewWaitGroup(ctx)

	// Empty cache is the version 1
	cache := NewCache()
	acker := NewAckingResourceMutatorWrapper(cache)
	require.Empty(t, acker.ackedVersions)

	// Create version 2 with resource 0.
	callback, comp := newCompCallback()
	acker.Upsert(typeURL, resources[0].Name, resources[0], []string{node0}, wg, callback)
	require.Condition(t, isNotCompletedComparison(comp))
	require.Empty(t, acker.ackedVersions)

	// Ack the right version, for the right resource, from another node.
	acker.HandleResourceVersionAck(2, 2, node1, []string{resources[0].Name}, typeURL, "")
	require.Condition(t, isNotCompletedComparison(comp))
	require.Len(t, acker.ackedVersions, 1)
	require.Equal(t, uint64(2), acker.ackedVersions[node1])

	// Ack the right version, for another resource, from the right node.
	acker.HandleResourceVersionAck(2, 2, node0, []string{resources[1].Name}, typeURL, "")
	require.Condition(t, isNotCompletedComparison(comp))
	require.Len(t, acker.ackedVersions, 2)
	require.Equal(t, uint64(2), acker.ackedVersions[node0])

	// Ack an older version, for the right resource, from the right node.
	acker.HandleResourceVersionAck(1, 1, node0, []string{resources[0].Name}, typeURL, "")
	require.Condition(t, isNotCompletedComparison(comp))
	require.Len(t, acker.ackedVersions, 2)
	require.Equal(t, uint64(2), acker.ackedVersions[node0])

	// Ack the right version, for the right resource, from the right node.
	acker.HandleResourceVersionAck(2, 2, node0, []string{resources[0].Name}, typeURL, "")
	require.Condition(t, completedComparison(comp))
	require.Len(t, acker.ackedVersions, 2)
	require.Equal(t, uint64(2), acker.ackedVersions[node0])
}

func TestUseCurrent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"
	wg := completion.NewWaitGroup(ctx)

	// Empty cache is the version 1
	cache := NewCache()
	acker := NewAckingResourceMutatorWrapper(cache)
	require.Empty(t, acker.ackedVersions)

	// Create version 2 with resource 0.
	callback, comp := newCompCallback()
	acker.Upsert(typeURL, resources[0].Name, resources[0], []string{node0}, wg, callback)
	require.Condition(t, isNotCompletedComparison(comp))
	require.Empty(t, acker.ackedVersions)
	require.Len(t, acker.pendingCompletions, 1)

	// Ack the right version, for the right resource, from another node.
	acker.HandleResourceVersionAck(2, 2, node1, []string{resources[0].Name}, typeURL, "")
	require.Condition(t, isNotCompletedComparison(comp))
	require.Len(t, acker.ackedVersions, 1)
	require.Equal(t, uint64(2), acker.ackedVersions[node1])
	require.Len(t, acker.pendingCompletions, 1)

	// Use current version, not yet acked
	acker.UseCurrent(typeURL, []string{node0}, wg)
	require.Len(t, acker.pendingCompletions, 2)

	// Ack the right version, for another resource, from the right node.
	acker.HandleResourceVersionAck(2, 2, node0, []string{resources[1].Name}, typeURL, "")
	require.Condition(t, isNotCompletedComparison(comp))
	require.Len(t, acker.ackedVersions, 2)
	require.Equal(t, uint64(2), acker.ackedVersions[node0])
	// UseCurrent ignores resource names, so an ack of the same or later version from the right node will complete it
	require.Len(t, acker.pendingCompletions, 1)

	// Ack an older version, for the right resource, from the right node.
	acker.HandleResourceVersionAck(1, 1, node0, []string{resources[0].Name}, typeURL, "")
	require.Condition(t, isNotCompletedComparison(comp))
	require.Len(t, acker.ackedVersions, 2)
	require.Equal(t, uint64(2), acker.ackedVersions[node0])
	require.Len(t, acker.pendingCompletions, 1)

	// Ack the right version, for the right resource, from the right node.
	acker.HandleResourceVersionAck(2, 2, node0, []string{resources[0].Name}, typeURL, "")
	require.Condition(t, completedComparison(comp))
	require.Len(t, acker.ackedVersions, 2)
	require.Equal(t, uint64(2), acker.ackedVersions[node0])
	require.Empty(t, acker.pendingCompletions)
}

func TestUseCurrentSkipsNodesThatAlreadyAckedCurrentVersion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"
	baselineWG := completion.NewWaitGroup(ctx)

	cache := NewCache()
	acker := NewAckingResourceMutatorWrapper(cache)

	// Create version 2 and fully ACK it so both nodes have a shared baseline.
	callbackV2, compV2 := newCompCallback()
	acker.Upsert(typeURL, resources[0].Name, resources[0], []string{node0, node1}, baselineWG, callbackV2)
	acker.HandleResourceVersionAck(2, 2, node0, []string{resources[0].Name}, typeURL, "")
	acker.HandleResourceVersionAck(2, 2, node1, []string{resources[0].Name}, typeURL, "")
	require.Condition(t, completedComparison(compV2))
	require.NoError(t, baselineWG.Wait())
	require.Equal(t, uint64(2), acker.ackedVersions[node0])
	require.Equal(t, uint64(2), acker.ackedVersions[node1])

	// Create version 3, but only node0 ACKs it. Node1 remains outstanding.
	upsertV3WG := completion.NewWaitGroup(ctx)
	callbackV3, compV3 := newCompCallback()
	acker.Upsert(typeURL, resources[1].Name, resources[1], []string{node0, node1}, upsertV3WG, callbackV3)
	acker.HandleResourceVersionAck(3, 3, node0, []string{resources[1].Name}, typeURL, "")
	require.Condition(t, isNotCompletedComparison(compV3))
	require.Equal(t, uint64(3), acker.ackedVersions[node0])
	require.Equal(t, uint64(2), acker.ackedVersions[node1])
	require.Len(t, acker.pendingCompletions, 1)

	currentCtx, currentCancel := context.WithTimeout(context.Background(), MaxCompletionDuration)
	defer currentCancel()
	currentWG := completion.NewWaitGroup(currentCtx)

	// UseCurrent must only wait for node1, as node0 has already ACKed version 3.
	acker.UseCurrent(typeURL, []string{node0, node1}, currentWG)
	// There are now two outstanding waits for version 3:
	// 1. the original Upsert completion, still waiting for node1 to ACK resources[1]
	// 2. the new UseCurrent completion, which should only wait for nodes that have not ACKed
	//    the current version yet.
	// If the old bug regresses, UseCurrent would add node0 again and the wait below would need
	// another ACK from node0 before completing.
	require.Len(t, acker.pendingCompletions, 2)

	var useCurrentPending *pendingCompletion
	for _, pending := range acker.pendingCompletions {
		// Both pending completions target the current version, so identify the UseCurrent
		// one by its shape: it tracks nodes only, therefore node1 is present with a nil
		// resource set.  The Upsert completion instead tracks per-resource ACKs, so its
		// node entry has a non-nil resource-name map.
		if pending.version == acker.version {
			if remaining, found := pending.remainingNodesResources[node1]; found && remaining == nil {
				useCurrentPending = pending
				break
			}
		}
	}
	require.NotNil(t, useCurrentPending)
	require.Len(t, useCurrentPending.remainingNodesResources, 1)
	require.Contains(t, useCurrentPending.remainingNodesResources, node1)
	require.NotContains(t, useCurrentPending.remainingNodesResources, node0)

	// ACKing node1 for version 3 must complete the UseCurrent wait without requiring a new ACK from node0.
	acker.HandleResourceVersionAck(3, 3, node1, []string{resources[1].Name}, typeURL, "")
	// The same ACK must also complete the original Upsert completion for version 3.
	require.Condition(t, completedComparison(compV3))
	require.NoError(t, upsertV3WG.Wait())
	require.NoError(t, currentWG.Wait())
	require.Empty(t, acker.pendingCompletions)
}

func TestCancelCompletions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	typeURL1 := "type.googleapis.com/envoy.config.v3.DummyConfiguration"
	typeURL2 := "type.googleapis.com/envoy.config.v3.AnotherConfiguration"
	wg := completion.NewWaitGroup(ctx)

	cache := NewCache()
	acker := NewAckingResourceMutatorWrapper(cache)
	require.Empty(t, acker.ackedVersions)

	// Add one pending completion for each type.
	callback1, comp1 := newCompCallback()
	acker.Upsert(typeURL1, resources[0].Name, resources[0], []string{node0}, wg, callback1)
	require.Condition(t, isNotCompletedComparison(comp1))

	callback2, comp2 := newCompCallback()
	acker.Upsert(typeURL2, resources[1].Name, resources[1], []string{node0}, wg, callback2)
	require.Condition(t, isNotCompletedComparison(comp2))
	require.Len(t, acker.pendingCompletions, 2)

	// Cancel only the first type URL.
	acker.CancelCompletions(typeURL1)
	require.Condition(t, completedComparison(comp1))
	require.Condition(t, isNotCompletedComparison(comp2))
	require.Len(t, acker.pendingCompletions, 1)

	// Verify the other type still completes via ACK.
	acker.HandleResourceVersionAck(3, 3, node0, []string{resources[1].Name}, typeURL2, "")
	require.Condition(t, completedComparison(comp2))
	require.Empty(t, acker.pendingCompletions)
}

func TestUpsertMultipleNodes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"
	wg := completion.NewWaitGroup(ctx)

	// Empty cache is the version 1
	cache := NewCache()
	acker := NewAckingResourceMutatorWrapper(cache)
	require.Empty(t, acker.ackedVersions)

	// Create version 2 with resource 0.
	callback, comp := newCompCallback()
	acker.Upsert(typeURL, resources[0].Name, resources[0], []string{node0, node1}, wg, callback)
	require.Condition(t, isNotCompletedComparison(comp))
	require.False(t, acker.currentVersionAcked([]string{node0}))
	require.False(t, acker.currentVersionAcked([]string{node1}))
	require.False(t, acker.currentVersionAcked([]string{node2}))

	// Ack the right version, for the right resource, from another node.
	acker.HandleResourceVersionAck(2, 2, node2, []string{resources[0].Name}, typeURL, "")
	require.Condition(t, isNotCompletedComparison(comp))
	require.False(t, acker.currentVersionAcked([]string{node0}))
	require.False(t, acker.currentVersionAcked([]string{node1}))
	require.True(t, acker.currentVersionAcked([]string{node2}))

	// Ack the right version, for the right resource, from one of the nodes (node0).
	// One of the nodes (node1) still needs to ACK.
	acker.HandleResourceVersionAck(2, 2, node0, []string{resources[0].Name}, typeURL, "")
	require.Condition(t, isNotCompletedComparison(comp))
	require.True(t, acker.currentVersionAcked([]string{node0}))
	require.False(t, acker.currentVersionAcked([]string{node1}))
	require.True(t, acker.currentVersionAcked([]string{node2}))
	require.False(t, acker.currentVersionAcked([]string{node0, node1}))
	require.True(t, acker.currentVersionAcked([]string{node0, node2}))

	// Ack the right version, for the right resource, from the last remaining node (node1).
	acker.HandleResourceVersionAck(2, 2, node1, []string{resources[0].Name}, typeURL, "")
	require.Condition(t, completedComparison(comp))
	require.True(t, acker.currentVersionAcked([]string{node0}))
	require.True(t, acker.currentVersionAcked([]string{node1}))
	require.True(t, acker.currentVersionAcked([]string{node2}))
	require.True(t, acker.currentVersionAcked([]string{node0, node1, node2}))
}

func TestUpsertMoreRecentVersion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"
	wg := completion.NewWaitGroup(ctx)

	// Empty cache is the version 1
	cache := NewCache()
	acker := NewAckingResourceMutatorWrapper(cache)

	// Create version 2 with resource 0.
	callback, comp := newCompCallback()
	acker.Upsert(typeURL, resources[0].Name, resources[0], []string{node0}, wg, callback)
	require.Condition(t, isNotCompletedComparison(comp))

	// Ack an older version, for the right resource, from the right node.
	acker.HandleResourceVersionAck(1, 1, node0, []string{resources[0].Name}, typeURL, "")
	require.Condition(t, isNotCompletedComparison(comp))

	// Ack a more recent version, for the right resource, from the right node.
	acker.HandleResourceVersionAck(123, 123, node0, []string{resources[0].Name}, typeURL, "")
	require.Condition(t, completedComparison(comp))
}

func TestUpsertMoreRecentVersionNack(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"
	wg := completion.NewWaitGroup(ctx)

	// Empty cache is the version 1
	cache := NewCache()
	acker := NewAckingResourceMutatorWrapper(cache)

	// Create version 2 with resource 0.
	callback, comp := newCompCallback()
	acker.Upsert(typeURL, resources[0].Name, resources[0], []string{node0}, wg, callback)
	require.Condition(t, isNotCompletedComparison(comp))

	// Ack an older version, for the right resource, from the right node.
	acker.HandleResourceVersionAck(1, 1, node0, []string{resources[0].Name}, typeURL, "")
	require.Condition(t, isNotCompletedComparison(comp))

	// NAck a more recent version, for the right resource, from the right node.
	acker.HandleResourceVersionAck(1, 2, node0, []string{resources[0].Name}, typeURL, "Detail")
	// IsCompleted is true only for completions without error
	require.Condition(t, isNotCompletedComparison(comp))
	require.Error(t, comp.Err())
	require.EqualValues(t, &ProxyError{Err: ErrNackReceived, Detail: "Detail"}, comp.Err())
}

func TestDeleteSingleNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"
	wg := completion.NewWaitGroup(ctx)

	// Empty cache is the version 1
	cache := NewCache()
	acker := NewAckingResourceMutatorWrapper(cache)

	// Create version 2 with resource 0.
	callback, comp := newCompCallback()
	acker.Upsert(typeURL, resources[0].Name, resources[0], []string{node0}, wg, callback)
	require.Condition(t, isNotCompletedComparison(comp))

	// Ack the right version, for the right resource, from the right node.
	acker.HandleResourceVersionAck(2, 2, node0, []string{resources[0].Name}, typeURL, "")
	require.Condition(t, completedComparison(comp))

	// Create version 3 with no resources.
	callback, comp = newCompCallback()
	acker.Delete(typeURL, resources[0].Name, []string{node0}, wg, callback)
	require.Condition(t, isNotCompletedComparison(comp))

	// Ack the right version, for another resource, from another node.
	acker.HandleResourceVersionAck(3, 3, node1, []string{resources[2].Name}, typeURL, "")
	require.Condition(t, isNotCompletedComparison(comp))

	// Ack the right version, for another resource, from the right node.
	acker.HandleResourceVersionAck(3, 3, node0, []string{resources[2].Name}, typeURL, "")
	// The resource name is ignored. For delete, we only consider the version.
	require.Condition(t, completedComparison(comp))
}

func TestUpsertCompletionAfterDeletedResource(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"
	wg := completion.NewWaitGroup(ctx)

	// Empty cache is the version 1
	cache := NewCache()
	acker := NewAckingResourceMutatorWrapper(cache)

	// Create version 2 with resource 0 and a completion that waits for ACK.
	callback, comp := newCompCallback()
	acker.Upsert(typeURL, resources[0].Name, resources[0], []string{node0}, wg, callback)
	require.Condition(t, isNotCompletedComparison(comp))
	require.Len(t, acker.pendingCompletions, 1)
	require.Equal(t, uint64(2), acker.version)

	// Delete the same resource before the ACK for version 2 is received.
	acker.Delete(typeURL, resources[0].Name, nil, nil, nil)
	require.Condition(t, isNotCompletedComparison(comp))
	require.Len(t, acker.pendingCompletions, 1)
	require.Equal(t, uint64(3), acker.version)

	// The pending completion must still be keyed by node so that ACK processing
	// can find it, even though there are no resource names left.
	for _, pending := range acker.pendingCompletions {
		require.Equal(t, typeURL, pending.typeURL)
		require.Contains(t, pending.remainingNodesResources, node0)
		require.Empty(t, pending.remainingNodesResources[node0])
	}

	// ACK the newer version from the right node with a different resource name.
	// This should complete the pending upsert completion after delete pruning.
	acker.HandleResourceVersionAck(3, 3, node0, []string{resources[2].Name}, typeURL, "")
	require.Condition(t, completedComparison(comp))
	require.Empty(t, acker.pendingCompletions)
}

func TestDeleteMultipleNodes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"
	wg := completion.NewWaitGroup(ctx)

	// Empty cache is the version 1
	cache := NewCache()
	acker := NewAckingResourceMutatorWrapper(cache)

	// Create version 2 with resource 0.
	callback, comp := newCompCallback()
	acker.Upsert(typeURL, resources[0].Name, resources[0], []string{node0}, wg, callback)
	require.Condition(t, isNotCompletedComparison(comp))

	// Ack the right version, for the right resource, from the right node.
	acker.HandleResourceVersionAck(2, 2, node0, []string{resources[0].Name}, typeURL, "")
	require.Condition(t, completedComparison(comp))

	// Create version 3 with no resources.
	callback, comp = newCompCallback()
	acker.Delete(typeURL, resources[0].Name, []string{node0, node1}, wg, callback)
	require.Condition(t, isNotCompletedComparison(comp))

	// Ack the right version, for another resource, from one of the nodes.
	acker.HandleResourceVersionAck(3, 3, node1, []string{resources[2].Name}, typeURL, "")
	require.Condition(t, isNotCompletedComparison(comp))

	// Ack the right version, for another resource, from the remaining node.
	acker.HandleResourceVersionAck(3, 3, node0, []string{resources[2].Name}, typeURL, "")
	// The resource name is ignored. For delete, we only consider the version.
	require.Condition(t, completedComparison(comp))
}

func TestRevertInsert(t *testing.T) {
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"

	cache := NewCache()
	acker := NewAckingResourceMutatorWrapper(cache)

	// Create version 1 with resource 0.
	// Insert.
	revert := acker.Upsert(typeURL, resources[0].Name, resources[0], []string{node0}, nil, nil)

	// Insert another resource.
	_ = acker.Upsert(typeURL, resources[2].Name, resources[2], []string{node0}, nil, nil)

	res, err := cache.Lookup(typeURL, resources[0].Name)
	require.NoError(t, err)
	require.Equal(t, resources[0], res)

	res, err = cache.Lookup(typeURL, resources[2].Name)
	require.NoError(t, err)
	require.Equal(t, resources[2], res)

	revert()

	res, err = cache.Lookup(typeURL, resources[0].Name)
	require.NoError(t, err)
	require.Nil(t, res)

	res, err = cache.Lookup(typeURL, resources[2].Name)
	require.NoError(t, err)
	require.Equal(t, resources[2], res)
}

func TestRevertUpdate(t *testing.T) {
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"

	cache := NewCache()
	acker := NewAckingResourceMutatorWrapper(cache)

	// Create version 1 with resource 0.
	// Insert.
	acker.Upsert(typeURL, resources[0].Name, resources[0], []string{node0}, nil, nil)

	// Insert another resource.
	_ = acker.Upsert(typeURL, resources[2].Name, resources[2], []string{node0}, nil, nil)

	res, err := cache.Lookup(typeURL, resources[0].Name)
	require.NoError(t, err)
	require.Equal(t, resources[0], res)

	res, err = cache.Lookup(typeURL, resources[2].Name)
	require.NoError(t, err)
	require.Equal(t, resources[2], res)

	// Update.
	revert := acker.Upsert(typeURL, resources[0].Name, resources[1], []string{node0}, nil, nil)

	res, err = cache.Lookup(typeURL, resources[0].Name)
	require.NoError(t, err)
	require.Equal(t, resources[1], res)

	revert()

	res, err = cache.Lookup(typeURL, resources[0].Name)
	require.NoError(t, err)
	require.Equal(t, resources[0], res)

	res, err = cache.Lookup(typeURL, resources[2].Name)
	require.NoError(t, err)
	require.Equal(t, resources[2], res)
}

func TestRevertDelete(t *testing.T) {
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"

	cache := NewCache()
	acker := NewAckingResourceMutatorWrapper(cache)

	// Create version 1 with resource 0.
	// Insert.
	acker.Upsert(typeURL, resources[0].Name, resources[0], []string{node0}, nil, nil)

	// Insert another resource.
	_ = acker.Upsert(typeURL, resources[2].Name, resources[2], []string{node0}, nil, nil)

	res, err := cache.Lookup(typeURL, resources[0].Name)
	require.NoError(t, err)
	require.Equal(t, resources[0], res)

	res, err = cache.Lookup(typeURL, resources[2].Name)
	require.NoError(t, err)
	require.Equal(t, resources[2], res)

	// Delete.
	revert := acker.Delete(typeURL, resources[0].Name, []string{node0}, nil, nil)

	res, err = cache.Lookup(typeURL, resources[0].Name)
	require.NoError(t, err)
	require.Nil(t, res)

	res, err = cache.Lookup(typeURL, resources[2].Name)
	require.NoError(t, err)
	require.Equal(t, resources[2], res)

	revert()

	res, err = cache.Lookup(typeURL, resources[0].Name)
	require.NoError(t, err)
	require.Equal(t, resources[0], res)

	res, err = cache.Lookup(typeURL, resources[2].Name)
	require.NoError(t, err)
	require.Equal(t, resources[2], res)
}
