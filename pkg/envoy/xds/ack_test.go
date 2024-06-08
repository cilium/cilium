// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/completion"
)

const (
	node0 = "10.0.0.0"
	node1 = "10.0.0.1"
	node2 = "10.0.0.2"

	MaxCompletionDuration = 250 * time.Millisecond
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
		return completedInTime(comp)
	}
}

func isNotCompletedComparison(comp *compCheck) assert.Comparison {
	return func() bool {
		return !completedInTime(comp)
	}
}

func completedInTime(comp *compCheck) bool {
	if comp == nil {
		return false
	}

	if comp.err != nil {
		return false
	}

	select {
	case comp.err = <-comp.ch:
		return comp.err == nil
	case <-time.After(MaxCompletionDuration):
		return false
	}
}

func TestUpsertSingleNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"
	wg := completion.NewWaitGroup(ctx)

	// Empty cache is the version 1
	cache := NewCache()
	acker := NewAckingResourceMutatorWrapper(cache)
	require.Len(t, acker.ackedVersions, 0)

	// Create version 2 with resource 0.
	callback, comp := newCompCallback()
	acker.Upsert(typeURL, resources[0].Name, resources[0], []string{node0}, wg, callback)
	require.Condition(t, isNotCompletedComparison(comp))
	require.Len(t, acker.ackedVersions, 0)

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

// UseCurrent adds a completion to the WaitGroup if the current
// version of the cached resource has not been acked yet, allowing the
// caller to wait for the ACK.
func (m *AckingResourceMutatorWrapper) UseCurrent(typeURL string, nodeIDs []string, wg *completion.WaitGroup) {
	m.locker.Lock()
	defer m.locker.Unlock()

	if wg != nil {
		m.useCurrent(typeURL, nodeIDs, wg, nil)
	}
}

func TestUseCurrent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"
	wg := completion.NewWaitGroup(ctx)

	// Empty cache is the version 1
	cache := NewCache()
	acker := NewAckingResourceMutatorWrapper(cache)
	require.Len(t, acker.ackedVersions, 0)

	// Create version 2 with resource 0.
	callback, comp := newCompCallback()
	acker.Upsert(typeURL, resources[0].Name, resources[0], []string{node0}, wg, callback)
	require.Condition(t, isNotCompletedComparison(comp))
	require.Len(t, acker.ackedVersions, 0)
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
	require.Len(t, acker.pendingCompletions, 0)
}

func TestUpsertMultipleNodes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"
	wg := completion.NewWaitGroup(ctx)

	// Empty cache is the version 1
	cache := NewCache()
	acker := NewAckingResourceMutatorWrapper(cache)
	require.Len(t, acker.ackedVersions, 0)

	// Create version 2 with resource 0.
	callback, comp := newCompCallback()
	acker.Upsert(typeURL, resources[0].Name, resources[0], []string{node0, node1}, wg, callback)
	require.Condition(t, isNotCompletedComparison(comp))
	require.Equal(t, false, acker.currentVersionAcked([]string{node0}))
	require.Equal(t, false, acker.currentVersionAcked([]string{node1}))
	require.Equal(t, false, acker.currentVersionAcked([]string{node2}))

	// Ack the right version, for the right resource, from another node.
	acker.HandleResourceVersionAck(2, 2, node2, []string{resources[0].Name}, typeURL, "")
	require.Condition(t, isNotCompletedComparison(comp))
	require.Equal(t, false, acker.currentVersionAcked([]string{node0}))
	require.Equal(t, false, acker.currentVersionAcked([]string{node1}))
	require.Equal(t, true, acker.currentVersionAcked([]string{node2}))

	// Ack the right version, for the right resource, from one of the nodes (node0).
	// One of the nodes (node1) still needs to ACK.
	acker.HandleResourceVersionAck(2, 2, node0, []string{resources[0].Name}, typeURL, "")
	require.Condition(t, isNotCompletedComparison(comp))
	require.Equal(t, true, acker.currentVersionAcked([]string{node0}))
	require.Equal(t, false, acker.currentVersionAcked([]string{node1}))
	require.Equal(t, true, acker.currentVersionAcked([]string{node2}))
	require.Equal(t, false, acker.currentVersionAcked([]string{node0, node1}))
	require.Equal(t, true, acker.currentVersionAcked([]string{node0, node2}))

	// Ack the right version, for the right resource, from the last remaining node (node1).
	acker.HandleResourceVersionAck(2, 2, node1, []string{resources[0].Name}, typeURL, "")
	require.Condition(t, completedComparison(comp))
	require.Equal(t, true, acker.currentVersionAcked([]string{node0}))
	require.Equal(t, true, acker.currentVersionAcked([]string{node1}))
	require.Equal(t, true, acker.currentVersionAcked([]string{node2}))
	require.Equal(t, true, acker.currentVersionAcked([]string{node0, node1, node2}))
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
	require.NotEqual(t, nil, comp.Err())
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"
	wg := completion.NewWaitGroup(ctx)

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

	comp := wg.AddCompletion()
	defer comp.Complete(nil)
	revert(comp)

	res, err = cache.Lookup(typeURL, resources[0].Name)
	require.NoError(t, err)
	require.Nil(t, res)

	res, err = cache.Lookup(typeURL, resources[2].Name)
	require.NoError(t, err)
	require.Equal(t, resources[2], res)
}

func TestRevertUpdate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"
	wg := completion.NewWaitGroup(ctx)

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

	comp := wg.AddCompletion()
	defer comp.Complete(nil)
	revert(comp)

	res, err = cache.Lookup(typeURL, resources[0].Name)
	require.NoError(t, err)
	require.Equal(t, resources[0], res)

	res, err = cache.Lookup(typeURL, resources[2].Name)
	require.NoError(t, err)
	require.Equal(t, resources[2], res)
}

func TestRevertDelete(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"
	wg := completion.NewWaitGroup(ctx)

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

	comp := wg.AddCompletion()
	defer comp.Complete(nil)
	revert(comp)

	res, err = cache.Lookup(typeURL, resources[0].Name)
	require.NoError(t, err)
	require.Equal(t, resources[0], res)

	res, err = cache.Lookup(typeURL, resources[2].Name)
	require.NoError(t, err)
	require.Equal(t, resources[2], res)
}
