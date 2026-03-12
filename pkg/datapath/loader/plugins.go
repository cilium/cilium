// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"sort"
	"strings"
)

type node struct {
	exists        bool
	outgoing      map[string]struct{}
	incomingCount int
}

// a pluginDependencyGraph is a DAG that tracks dependencies between plugins for
// a particular hook point.
type pluginDependencyGraph map[string]*node

// sort performs a topological sort that respects all ordering constraints. It
// consumes g in the process.
func (g pluginDependencyGraph) sort() ([]string, error) {
	var empty []string
	sorted := make([]string, 0, len(g))

	for p, n := range g {
		if n.incomingCount == 0 {
			empty = append(empty, p)
		}
	}

	for len(empty) > 0 {
		if g[empty[0]].exists {
			sorted = append(sorted, empty[0])

			for after := range g[empty[0]].outgoing {
				g[after].incomingCount--

				if g[after].incomingCount == 0 {
					empty = append(empty, after)
				}
			}
		}

		delete(g, empty[0])
		empty = empty[1:]
	}

	if len(g) > 0 {
		// if a cycle exists, find a cycle and report it.
		return nil, g.findDependencyCycle()
	}

	return sorted, nil
}

func (g pluginDependencyGraph) ensureNode(name string) {
	if g[name] == nil {
		g[name] = &node{
			outgoing: map[string]struct{}{},
		}
	}
}

// addNode marks a plugin as actually existing and not just something referenced
// by another plugin.
func (g pluginDependencyGraph) addNode(name string) {
	g.ensureNode(name)
	g[name].exists = true
}

// before marks that a should come before b.
func (g pluginDependencyGraph) before(a, b string) {
	g.after(b, a)
}

// after marks that a should come after b.
func (g pluginDependencyGraph) after(a, b string) {
	g.ensureNode(a)
	g.ensureNode(b)
	if _, exists := g[b].outgoing[a]; !exists {
		g[b].outgoing[a] = struct{}{}
		g[a].incomingCount++
	}
}

// sortedNodes sorts plugins by name in ascending order.
func (g pluginDependencyGraph) sortedNodes() []string {
	var nodes []string

	for n := range g {
		nodes = append(nodes, n)
	}

	sort.Strings(nodes)
	return nodes
}

// sortedNodes sorts after dependencies for plugin n in ascending order.
func (g pluginDependencyGraph) sortedOutgoing(n string) []string {
	var outgoing []string

	for o := range g[n].outgoing {
		outgoing = append(outgoing, o)
	}

	sort.Strings(outgoing)
	return outgoing
}

// findDependencyCycle finds a cycle in the DAG and reports it back as a
// dependencyCycleError.
func (g pluginDependencyGraph) findDependencyCycle() error {
	var findCycle func(node string, path []string, visited map[string]bool) []string
	findCycle = func(node string, path []string, visited map[string]bool) []string {
		if visited[node] {
			return path
		}

		visited[node] = true
		for _, after := range g.sortedOutgoing(node) {
			path = append(path, after)
			if cycle := findCycle(after, path, visited); cycle != nil {
				return cycle
			}
			path = path[:len(path)-1]
		}
		visited[node] = false

		return nil
	}

	var cycle []string

	for _, n := range g.sortedNodes() {
		cycle = findCycle(n, []string{n}, map[string]bool{})
		if cycle != nil {
			break
		}
	}

	return &dependencyCycleError{
		cycle: cycle,
	}
}

type dependencyCycleError struct {
	cycle []string
}

func (err *dependencyCycleError) Error() string {
	var b strings.Builder
	b.WriteString("dependency cycle: ")

	for i, p := range err.cycle {
		b.WriteString(p)
		if i != len(err.cycle)-1 {
			b.WriteString("->")
		}
	}

	return b.String()
}
