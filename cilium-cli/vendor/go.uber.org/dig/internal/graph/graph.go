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

package graph

// Graph represents a simple interface for representation
// of a directed graph.
// It is assumed that each node in the graph is uniquely
// identified with an incremental positive integer (i.e. 1, 2, 3...).
// A value of 0 for a node represents a sentinel error value.
type Graph interface {
	// Order returns the total number of nodes in the graph
	Order() int

	// EdgesFrom returns a list of integers that each
	// represents a node that has an edge from node u.
	EdgesFrom(u int) []int
}

// IsAcyclic uses depth-first search to find cycles
// in a generic graph represented by Graph interface.
// If a cycle is found, it returns a list of nodes that
// are in the cyclic path, identified by their orders.
func IsAcyclic(g Graph) (bool, []int) {
	// cycleStart is a node that introduces a cycle in
	// the graph. Values in the range [1, g.Order()) mean
	// that there exists a cycle in g.
	info := newCycleInfo(g.Order())

	for i := 0; i < g.Order(); i++ {
		info.Reset()

		cycle := isAcyclic(g, i, info, nil /* cycle path */)
		if len(cycle) > 0 {
			return false, cycle
		}
	}

	return true, nil
}

// isAcyclic traverses the given graph starting from a specific node
// using depth-first search using recursion. If a cycle is detected,
// it returns the node that contains the "last" edge that introduces
// a cycle.
// For example, running isAcyclic starting from 1 on the following
// graph will return 3.
//
//	1 -> 2 -> 3 -> 1
func isAcyclic(g Graph, u int, info cycleInfo, path []int) []int {
	// We've already verified that there are no cycles from this node.
	if info[u].Visited {
		return nil
	}
	info[u].Visited = true
	info[u].OnStack = true

	path = append(path, u)
	for _, v := range g.EdgesFrom(u) {
		if !info[v].Visited {
			if cycle := isAcyclic(g, v, info, path); len(cycle) > 0 {
				return cycle
			}
		} else if info[v].OnStack {
			// We've found a cycle, and we have a full path back.
			// Prune it down to just the cyclic nodes.
			cycle := path
			for i := len(cycle) - 1; i >= 0; i-- {
				if cycle[i] == v {
					cycle = cycle[i:]
					break
				}
			}

			// Complete the cycle by adding this node to it.
			return append(cycle, v)
		}
	}
	info[u].OnStack = false
	return nil
}

// cycleNode keeps track of a single node's info for cycle detection.
type cycleNode struct {
	Visited bool
	OnStack bool
}

// cycleInfo contains information about each node while we're trying to find
// cycles.
type cycleInfo []cycleNode

func newCycleInfo(order int) cycleInfo {
	return make(cycleInfo, order)
}

func (info cycleInfo) Reset() {
	for i := range info {
		info[i].OnStack = false
	}
}
