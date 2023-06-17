// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"time"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/completion"
)

type AckSuite struct{}

var _ = Suite(&AckSuite{})

const (
	node0 = "10.0.0.0"
	node1 = "10.0.0.1"
	node2 = "10.0.0.2"
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

// IsCompletedChecker checks that a Completion is completed without errors.
type IsCompletedChecker struct {
	*CheckerInfo
}

func (c *IsCompletedChecker) Check(params []interface{}, names []string) (result bool, err string) {
	comp, ok := params[0].(*compCheck)
	if !ok {
		return false, "completion must be a *compCheck"
	}
	if comp == nil {
		return false, "completion is nil"
	}

	// receive from a closed channel returns nil, so test for a previous error before trying again
	if comp.err != nil {
		return false, err
	}

	select {
	case comp.err = <-comp.ch:
		return comp.err == nil, err
	default:
		return false, "not completed yet"
	}
}

// IsCompleted checks that a Completion is completed.
var IsCompleted Checker = &IsCompletedChecker{
	&CheckerInfo{Name: "IsCompleted", Params: []string{
		"completion"}},
}

func (s *AckSuite) TestUpsertSingleNode(c *C) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"
	wg := completion.NewWaitGroup(ctx)

	// Empty cache is the version 1
	cache := NewCache()
	acker := NewAckingResourceMutatorWrapper(cache)
	c.Assert(acker.ackedVersions, HasLen, 0)

	// Create version 2 with resource 0.
	callback, comp := newCompCallback()
	acker.Upsert(typeURL, resources[0].Name, resources[0], []string{node0}, wg, callback)
	c.Assert(comp, Not(IsCompleted))
	c.Assert(acker.ackedVersions, HasLen, 0)

	// Ack the right version, for the right resource, from another node.
	acker.HandleResourceVersionAck(2, 2, node1, []string{resources[0].Name}, typeURL, "")
	c.Assert(comp, Not(IsCompleted))
	c.Assert(acker.ackedVersions, HasLen, 1)
	c.Assert(acker.ackedVersions[node1], Equals, uint64(2))

	// Ack the right version, for another resource, from the right node.
	acker.HandleResourceVersionAck(2, 2, node0, []string{resources[1].Name}, typeURL, "")
	c.Assert(comp, Not(IsCompleted))
	c.Assert(acker.ackedVersions, HasLen, 2)
	c.Assert(acker.ackedVersions[node0], Equals, uint64(2))

	// Ack an older version, for the right resource, from the right node.
	acker.HandleResourceVersionAck(1, 1, node0, []string{resources[0].Name}, typeURL, "")
	c.Assert(comp, Not(IsCompleted))
	c.Assert(acker.ackedVersions, HasLen, 2)
	c.Assert(acker.ackedVersions[node0], Equals, uint64(2))

	// Ack the right version, for the right resource, from the right node.
	acker.HandleResourceVersionAck(2, 2, node0, []string{resources[0].Name}, typeURL, "")
	c.Assert(comp, IsCompleted)
	c.Assert(acker.ackedVersions, HasLen, 2)
	c.Assert(acker.ackedVersions[node0], Equals, uint64(2))
}

func (s *AckSuite) TestUseCurrent(c *C) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"
	wg := completion.NewWaitGroup(ctx)

	// Empty cache is the version 1
	cache := NewCache()
	acker := NewAckingResourceMutatorWrapper(cache)
	c.Assert(acker.ackedVersions, HasLen, 0)

	// Create version 2 with resource 0.
	callback, comp := newCompCallback()
	acker.Upsert(typeURL, resources[0].Name, resources[0], []string{node0}, wg, callback)
	c.Assert(comp, Not(IsCompleted))
	c.Assert(acker.ackedVersions, HasLen, 0)
	c.Assert(acker.pendingCompletions, HasLen, 1)

	// Ack the right version, for the right resource, from another node.
	acker.HandleResourceVersionAck(2, 2, node1, []string{resources[0].Name}, typeURL, "")
	c.Assert(comp, Not(IsCompleted))
	c.Assert(acker.ackedVersions, HasLen, 1)
	c.Assert(acker.ackedVersions[node1], Equals, uint64(2))
	c.Assert(acker.pendingCompletions, HasLen, 1)

	// Use current version, not yet acked
	acker.UseCurrent(typeURL, []string{node0}, wg)
	c.Assert(acker.pendingCompletions, HasLen, 2)

	// Ack the right version, for another resource, from the right node.
	acker.HandleResourceVersionAck(2, 2, node0, []string{resources[1].Name}, typeURL, "")
	c.Assert(comp, Not(IsCompleted))
	c.Assert(acker.ackedVersions, HasLen, 2)
	c.Assert(acker.ackedVersions[node0], Equals, uint64(2))
	// UseCurrent ignores resource names, so an ack of the same or later version from the right node will complete it
	c.Assert(acker.pendingCompletions, HasLen, 1)

	// Ack an older version, for the right resource, from the right node.
	acker.HandleResourceVersionAck(1, 1, node0, []string{resources[0].Name}, typeURL, "")
	c.Assert(comp, Not(IsCompleted))
	c.Assert(acker.ackedVersions, HasLen, 2)
	c.Assert(acker.ackedVersions[node0], Equals, uint64(2))
	c.Assert(acker.pendingCompletions, HasLen, 1)

	// Ack the right version, for the right resource, from the right node.
	acker.HandleResourceVersionAck(2, 2, node0, []string{resources[0].Name}, typeURL, "")
	c.Assert(comp, IsCompleted)
	c.Assert(acker.ackedVersions, HasLen, 2)
	c.Assert(acker.ackedVersions[node0], Equals, uint64(2))
	c.Assert(acker.pendingCompletions, HasLen, 0)
}

func (s *AckSuite) TestUpsertMultipleNodes(c *C) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	typeURL := "type.googleapis.com/envoy.config.v3.DummyConfiguration"
	wg := completion.NewWaitGroup(ctx)

	// Empty cache is the version 1
	cache := NewCache()
	acker := NewAckingResourceMutatorWrapper(cache)
	c.Assert(acker.ackedVersions, HasLen, 0)

	// Create version 2 with resource 0.
	callback, comp := newCompCallback()
	acker.Upsert(typeURL, resources[0].Name, resources[0], []string{node0, node1}, wg, callback)
	c.Assert(comp, Not(IsCompleted))
	c.Assert(acker.currentVersionAcked([]string{node0}), Equals, false)
	c.Assert(acker.currentVersionAcked([]string{node1}), Equals, false)
	c.Assert(acker.currentVersionAcked([]string{node2}), Equals, false)

	// Ack the right version, for the right resource, from another node.
	acker.HandleResourceVersionAck(2, 2, node2, []string{resources[0].Name}, typeURL, "")
	c.Assert(comp, Not(IsCompleted))
	c.Assert(acker.currentVersionAcked([]string{node0}), Equals, false)
	c.Assert(acker.currentVersionAcked([]string{node1}), Equals, false)
	c.Assert(acker.currentVersionAcked([]string{node2}), Equals, true)

	// Ack the right version, for the right resource, from one of the nodes (node0).
	// One of the nodes (node1) still needs to ACK.
	acker.HandleResourceVersionAck(2, 2, node0, []string{resources[0].Name}, typeURL, "")
	c.Assert(comp, Not(IsCompleted))
	c.Assert(acker.currentVersionAcked([]string{node0}), Equals, true)
	c.Assert(acker.currentVersionAcked([]string{node1}), Equals, false)
	c.Assert(acker.currentVersionAcked([]string{node2}), Equals, true)
	c.Assert(acker.currentVersionAcked([]string{node0, node1}), Equals, false)
	c.Assert(acker.currentVersionAcked([]string{node0, node2}), Equals, true)

	// Ack the right version, for the right resource, from the last remaining node (node1).
	acker.HandleResourceVersionAck(2, 2, node1, []string{resources[0].Name}, typeURL, "")
	c.Assert(comp, IsCompleted)
	c.Assert(acker.currentVersionAcked([]string{node0}), Equals, true)
	c.Assert(acker.currentVersionAcked([]string{node1}), Equals, true)
	c.Assert(acker.currentVersionAcked([]string{node2}), Equals, true)
	c.Assert(acker.currentVersionAcked([]string{node0, node1, node2}), Equals, true)
}

func (s *AckSuite) TestUpsertMoreRecentVersion(c *C) {
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
	c.Assert(comp, Not(IsCompleted))

	// Ack an older version, for the right resource, from the right node.
	acker.HandleResourceVersionAck(1, 1, node0, []string{resources[0].Name}, typeURL, "")
	c.Assert(comp, Not(IsCompleted))

	// Ack a more recent version, for the right resource, from the right node.
	acker.HandleResourceVersionAck(123, 123, node0, []string{resources[0].Name}, typeURL, "")
	c.Assert(comp, IsCompleted)
}

func (s *AckSuite) TestUpsertMoreRecentVersionNack(c *C) {
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
	c.Assert(comp, Not(IsCompleted))

	// Ack an older version, for the right resource, from the right node.
	acker.HandleResourceVersionAck(1, 1, node0, []string{resources[0].Name}, typeURL, "")
	c.Assert(comp, Not(IsCompleted))

	// NAck a more recent version, for the right resource, from the right node.
	acker.HandleResourceVersionAck(1, 2, node0, []string{resources[0].Name}, typeURL, "Detail")
	// IsCompleted is true only for completions without error
	c.Assert(comp, Not(IsCompleted))
	c.Assert(comp.Err(), Not(Equals), nil)
	c.Assert(comp.Err(), checker.DeepEquals, &ProxyError{Err: ErrNackReceived, Detail: "Detail"})
}

func (s *AckSuite) TestDeleteSingleNode(c *C) {
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
	c.Assert(comp, Not(IsCompleted))

	// Ack the right version, for the right resource, from the right node.
	acker.HandleResourceVersionAck(2, 2, node0, []string{resources[0].Name}, typeURL, "")
	c.Assert(comp, IsCompleted)

	// Create version 3 with no resources.
	callback, comp = newCompCallback()
	acker.Delete(typeURL, resources[0].Name, []string{node0}, wg, callback)
	c.Assert(comp, Not(IsCompleted))

	// Ack the right version, for another resource, from another node.
	acker.HandleResourceVersionAck(3, 3, node1, []string{resources[2].Name}, typeURL, "")
	c.Assert(comp, Not(IsCompleted))

	// Ack the right version, for another resource, from the right node.
	acker.HandleResourceVersionAck(3, 3, node0, []string{resources[2].Name}, typeURL, "")
	// The resource name is ignored. For delete, we only consider the version.
	c.Assert(comp, IsCompleted)
}

func (s *AckSuite) TestDeleteMultipleNodes(c *C) {
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
	c.Assert(comp, Not(IsCompleted))

	// Ack the right version, for the right resource, from the right node.
	acker.HandleResourceVersionAck(2, 2, node0, []string{resources[0].Name}, typeURL, "")
	c.Assert(comp, IsCompleted)

	// Create version 3 with no resources.
	callback, comp = newCompCallback()
	acker.Delete(typeURL, resources[0].Name, []string{node0, node1}, wg, callback)
	c.Assert(comp, Not(IsCompleted))

	// Ack the right version, for another resource, from one of the nodes.
	acker.HandleResourceVersionAck(3, 3, node1, []string{resources[2].Name}, typeURL, "")
	c.Assert(comp, Not(IsCompleted))

	// Ack the right version, for another resource, from the remaining node.
	acker.HandleResourceVersionAck(3, 3, node0, []string{resources[2].Name}, typeURL, "")
	// The resource name is ignored. For delete, we only consider the version.
	c.Assert(comp, IsCompleted)
}

func (s *AckSuite) TestRevertInsert(c *C) {
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
	c.Assert(err, IsNil)
	c.Assert(res, Equals, resources[0])

	res, err = cache.Lookup(typeURL, resources[2].Name)
	c.Assert(err, IsNil)
	c.Assert(res, Equals, resources[2])

	comp := wg.AddCompletion()
	defer comp.Complete(nil)
	revert(comp)

	res, err = cache.Lookup(typeURL, resources[0].Name)
	c.Assert(err, IsNil)
	c.Assert(res, IsNil)

	res, err = cache.Lookup(typeURL, resources[2].Name)
	c.Assert(err, IsNil)
	c.Assert(res, Equals, resources[2])
}

func (s *AckSuite) TestRevertUpdate(c *C) {
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
	c.Assert(err, IsNil)
	c.Assert(res, Equals, resources[0])

	res, err = cache.Lookup(typeURL, resources[2].Name)
	c.Assert(err, IsNil)
	c.Assert(res, Equals, resources[2])

	// Update.
	revert := acker.Upsert(typeURL, resources[0].Name, resources[1], []string{node0}, nil, nil)

	res, err = cache.Lookup(typeURL, resources[0].Name)
	c.Assert(err, IsNil)
	c.Assert(res, Equals, resources[1])

	comp := wg.AddCompletion()
	defer comp.Complete(nil)
	revert(comp)

	res, err = cache.Lookup(typeURL, resources[0].Name)
	c.Assert(err, IsNil)
	c.Assert(res, Equals, resources[0])

	res, err = cache.Lookup(typeURL, resources[2].Name)
	c.Assert(err, IsNil)
	c.Assert(res, Equals, resources[2])
}

func (s *AckSuite) TestRevertDelete(c *C) {
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
	c.Assert(err, IsNil)
	c.Assert(res, Equals, resources[0])

	res, err = cache.Lookup(typeURL, resources[2].Name)
	c.Assert(err, IsNil)
	c.Assert(res, Equals, resources[2])

	// Delete.
	revert := acker.Delete(typeURL, resources[0].Name, []string{node0}, nil, nil)

	res, err = cache.Lookup(typeURL, resources[0].Name)
	c.Assert(err, IsNil)
	c.Assert(res, IsNil)

	res, err = cache.Lookup(typeURL, resources[2].Name)
	c.Assert(err, IsNil)
	c.Assert(res, Equals, resources[2])

	comp := wg.AddCompletion()
	defer comp.Complete(nil)
	revert(comp)

	res, err = cache.Lookup(typeURL, resources[0].Name)
	c.Assert(err, IsNil)
	c.Assert(res, Equals, resources[0])

	res, err = cache.Lookup(typeURL, resources[2].Name)
	c.Assert(err, IsNil)
	c.Assert(res, Equals, resources[2])
}
