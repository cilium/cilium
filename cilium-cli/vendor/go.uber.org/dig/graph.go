// Copyright (c) 2021 Uber Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package dig

import "go.uber.org/dig/internal/graph"

// graphNode is a single node in the dependency graph.
type graphNode struct {
	Wrapped interface{}
}

// graphHolder is the dependency graph of the container.
// It saves constructorNodes and paramGroupedSlice (value groups)
// as nodes in the graph.
// It implements the graph interface defined by internal/graph.
// It has 1-1 correspondence with the Scope whose graph it represents.
type graphHolder struct {
	// all the nodes defined in the graph.
	nodes []*graphNode

	// Scope whose graph this holder contains.
	s *Scope

	// Number of nodes in the graph at last snapshot.
	// -1 if no snapshot has been taken.
	snap int
}

var _ graph.Graph = (*graphHolder)(nil)

func newGraphHolder(s *Scope) *graphHolder {
	return &graphHolder{s: s, snap: -1}
}

func (gh *graphHolder) Order() int { return len(gh.nodes) }

// EdgesFrom returns the indices of nodes that are dependencies of node u.
//
// To do that, it needs to do one of the following:
//
// For constructor nodes, it retrieves the providers of the constructor's
// parameters from the container and reports their orders.
//
// For value group nodes, it retrieves the group providers from the container
// and reports their orders.
func (gh *graphHolder) EdgesFrom(u int) []int {
	var orders []int
	switch w := gh.Lookup(u).(type) {
	case *constructorNode:
		for _, param := range w.paramList.Params {
			orders = append(orders, getParamOrder(gh, param)...)
		}
	case *paramGroupedSlice:
		providers := gh.s.getAllGroupProviders(w.Group, w.Type.Elem())
		for _, provider := range providers {
			orders = append(orders, provider.Order(gh.s))
		}
	}
	return orders
}

// NewNode adds a new value to the graph and returns its order.
func (gh *graphHolder) NewNode(wrapped interface{}) int {
	order := len(gh.nodes)
	gh.nodes = append(gh.nodes, &graphNode{
		Wrapped: wrapped,
	})
	return order
}

// Lookup retrieves the value for the node with the given order.
// Lookup panics if i is invalid.
func (gh *graphHolder) Lookup(i int) interface{} {
	return gh.nodes[i].Wrapped
}

// Snapshot takes a temporary snapshot of the current state of the graph.
// Use with Rollback to undo changes to the graph.
//
// Only one snapshot is allowed at a time.
// Multiple calls to snapshot will overwrite prior snapshots.
func (gh *graphHolder) Snapshot() {
	gh.snap = len(gh.nodes)
}

// Rollback rolls back a snapshot to a previously captured state.
// This is a no-op if no snapshot was captured.
func (gh *graphHolder) Rollback() {
	if gh.snap < 0 {
		return
	}

	// nodes is an append-only list. To rollback, we just drop the
	// extraneous entries from the slice.
	gh.nodes = gh.nodes[:gh.snap]
	gh.snap = -1
}
