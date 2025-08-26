// Copyright (c) 2019 Uber Technologies, Inc.
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

package dot

import (
	"fmt"
	"reflect"
)

// ErrorType of a constructor or group is updated when they fail to build.
type ErrorType int

const (
	noError ErrorType = iota
	rootCause
	transitiveFailure
)

// CtorID is a unique numeric identifier for constructors.
type CtorID uintptr

// Ctor encodes a constructor provided to the container for the DOT graph.
type Ctor struct {
	Name        string
	Package     string
	File        string
	Line        int
	ID          CtorID
	Params      []*Param
	GroupParams []*Group
	Results     []*Result
	ErrorType   ErrorType
}

// removeParam deletes the dependency on the provided result's nodeKey.
// This is used to prune links to results of deleted constructors.
func (c *Ctor) removeParam(k nodeKey) {
	var pruned []*Param
	for _, p := range c.Params {
		if k != p.nodeKey() {
			pruned = append(pruned, p)
		}
	}
	c.Params = pruned
}

type nodeKey struct {
	t     reflect.Type
	name  string
	group string
}

// Node is a single node in a graph and is embedded into Params and Results.
type Node struct {
	Type  reflect.Type
	Name  string
	Group string
}

func (n *Node) nodeKey() nodeKey {
	return nodeKey{t: n.Type, name: n.Name, group: n.Group}
}

// Param is a parameter node in the graph. Parameters are the input to constructors.
type Param struct {
	*Node

	Optional bool
}

// Result is a result node in the graph. Results are the output of constructors.
type Result struct {
	*Node

	// GroupIndex is added to differentiate grouped values from one another.
	// Since grouped values have the same type and group, their Node / string
	// representations are the same so we need indices to uniquely identify
	// the values.
	GroupIndex int
}

// Group is a group node in the graph. Group represents an fx value group.
type Group struct {
	// Type is the type of values in the group.
	Type      reflect.Type
	Name      string
	Results   []*Result
	ErrorType ErrorType
}

func (g *Group) nodeKey() nodeKey {
	return nodeKey{t: g.Type, group: g.Name}
}

// TODO(rhang): Avoid linear search to discover group results that should be pruned.
func (g *Group) removeResult(r *Result) {
	var pruned []*Result
	for _, rg := range g.Results {
		if r.GroupIndex != rg.GroupIndex {
			pruned = append(pruned, rg)
		}
	}
	g.Results = pruned
}

// Graph is the DOT-format graph in a Container.
type Graph struct {
	Ctors   []*Ctor
	ctorMap map[CtorID]*Ctor

	Groups   []*Group
	groupMap map[nodeKey]*Group

	consumers map[nodeKey][]*Ctor

	Failed *FailedNodes
}

// FailedNodes is the nodes that failed in the graph.
type FailedNodes struct {
	// RootCauses is a list of the point of failures. They are the root causes
	// of failed invokes and can be either missing types (not provided) or
	// error types (error providing).
	RootCauses []*Result

	// TransitiveFailures is the list of nodes that failed to build due to
	// missing/failed dependencies.
	TransitiveFailures []*Result

	// ctors is a collection of failed constructors IDs that are populated as the graph is
	// traversed for errors.
	ctors map[CtorID]struct{}

	// Groups is a collection of failed groupKeys that is populated as the graph is traversed
	// for errors.
	groups map[nodeKey]struct{}
}

// NewGraph creates an empty graph.
func NewGraph() *Graph {
	return &Graph{
		ctorMap:   make(map[CtorID]*Ctor),
		groupMap:  make(map[nodeKey]*Group),
		consumers: make(map[nodeKey][]*Ctor),
		Failed: &FailedNodes{
			ctors:  make(map[CtorID]struct{}),
			groups: make(map[nodeKey]struct{}),
		},
	}
}

// NewGroup creates a new group with information in the groupKey.
func NewGroup(k nodeKey) *Group {
	return &Group{
		Type: k.t,
		Name: k.group,
	}
}

// AddCtor adds the constructor with paramList and resultList into the graph.
func (dg *Graph) AddCtor(c *Ctor, paramList []*Param, resultList []*Result) {
	var (
		params      []*Param
		groupParams []*Group
	)

	// Loop through the paramList to separate them into regular params and
	// grouped params. For grouped params, we use getGroup to find the actual
	// group.
	for _, param := range paramList {
		if param.Group == "" {
			// Not a value group.
			params = append(params, param)
			continue
		}

		k := nodeKey{t: param.Type.Elem(), group: param.Group}
		group := dg.getGroup(k)
		groupParams = append(groupParams, group)
	}

	for _, result := range resultList {
		// If the result is a grouped value, we want to update its GroupIndex
		// and add it to the Group.
		if result.Group != "" {
			dg.addToGroup(result, c.ID)
		}
	}

	c.Params = params
	c.GroupParams = groupParams
	c.Results = resultList

	// Track which constructors consume a parameter.
	for _, p := range paramList {
		k := p.nodeKey()
		dg.consumers[k] = append(dg.consumers[k], c)
	}

	dg.Ctors = append(dg.Ctors, c)
	dg.ctorMap[c.ID] = c
}

func (dg *Graph) failNode(r *Result, isRootCause bool) {
	if isRootCause {
		dg.addRootCause(r)
	} else {
		dg.addTransitiveFailure(r)
	}
}

// AddMissingNodes adds missing nodes to the list of failed Results in the graph.
func (dg *Graph) AddMissingNodes(results []*Result) {
	// The failure(s) are root causes if there are no other failures.
	isRootCause := len(dg.Failed.RootCauses) == 0

	for _, r := range results {
		dg.failNode(r, isRootCause)
	}
}

// FailNodes adds results to the list of failed Results in the graph, and
// updates the state of the constructor with the given id accordingly.
func (dg *Graph) FailNodes(results []*Result, id CtorID) {
	// This failure is the root cause if there are no other failures.
	isRootCause := len(dg.Failed.RootCauses) == 0
	dg.Failed.ctors[id] = struct{}{}

	for _, r := range results {
		dg.failNode(r, isRootCause)
	}

	if c, ok := dg.ctorMap[id]; ok {
		if isRootCause {
			c.ErrorType = rootCause
		} else {
			c.ErrorType = transitiveFailure
		}
	}
}

// FailGroupNodes finds and adds the failed grouped nodes to the list of failed
// Results in the graph, and updates the state of the group and constructor
// with the given id accordingly.
func (dg *Graph) FailGroupNodes(name string, t reflect.Type, id CtorID) {
	// This failure is the root cause if there are no other failures.
	isRootCause := len(dg.Failed.RootCauses) == 0

	k := nodeKey{t: t, group: name}
	group := dg.getGroup(k)

	// If the ctor does not exist it cannot be failed.
	if _, ok := dg.ctorMap[id]; !ok {
		return
	}

	// Track which constructors and groups have failed.
	dg.Failed.ctors[id] = struct{}{}
	dg.Failed.groups[k] = struct{}{}

	for _, r := range dg.ctorMap[id].Results {
		if r.Type == t && r.Group == name {
			dg.failNode(r, isRootCause)
		}
	}

	if c, ok := dg.ctorMap[id]; ok {
		if isRootCause {
			group.ErrorType = rootCause
			c.ErrorType = rootCause
		} else {
			group.ErrorType = transitiveFailure
			c.ErrorType = transitiveFailure
		}
	}
}

// getGroup finds the group by nodeKey from the graph. If it is not available,
// a new group is created and returned.
func (dg *Graph) getGroup(k nodeKey) *Group {
	g, ok := dg.groupMap[k]
	if !ok {
		g = NewGroup(k)
		dg.groupMap[k] = g
		dg.Groups = append(dg.Groups, g)
	}
	return g
}

// addToGroup adds a newly provided grouped result to the appropriate group.
func (dg *Graph) addToGroup(r *Result, id CtorID) {
	k := nodeKey{t: r.Type, group: r.Group}
	group := dg.getGroup(k)

	r.GroupIndex = len(group.Results)
	group.Results = append(group.Results, r)
}

// PruneSuccess removes elements from the graph that do not have failed results.
// Removing elements that do not have failing results makes the graph easier to debug,
// since non-failing nodes and edges can clutter the graph and don't help the user debug.
func (dg *Graph) PruneSuccess() {
	dg.pruneCtors(dg.Failed.ctors)
	dg.pruneGroups(dg.Failed.groups)
}

// pruneCtors removes constructors from the graph that do not have failing Results.
func (dg *Graph) pruneCtors(failed map[CtorID]struct{}) {
	var pruned []*Ctor
	for _, c := range dg.Ctors {
		if _, ok := failed[c.ID]; ok {
			pruned = append(pruned, c)
			continue
		}
		// If a constructor is deleted, the constructor's stale result references need to
		// be removed from that result's Group and/or consuming constructor.
		dg.pruneCtorParams(c, dg.consumers)
		dg.pruneGroupResults(c, dg.groupMap)
		delete(dg.ctorMap, c.ID)
	}

	dg.Ctors = pruned
}

// pruneGroups removes groups from the graph that do not have failing results.
func (dg *Graph) pruneGroups(failed map[nodeKey]struct{}) {
	var pruned []*Group
	for _, g := range dg.Groups {
		k := g.nodeKey()
		if _, ok := failed[k]; ok {
			pruned = append(pruned, g)
			continue
		}
		delete(dg.groupMap, k)
	}
	dg.Groups = pruned

	dg.pruneCtorGroupParams(dg.groupMap)
}

// pruneCtorParams removes results of the constructor argument that are still referenced in the
// Params of constructors that consume those results. If the results in the constructor are found
// in the params of a consuming constructor that result should be removed.
func (dg *Graph) pruneCtorParams(c *Ctor, consumers map[nodeKey][]*Ctor) {
	for _, r := range c.Results {
		for _, ctor := range consumers[r.nodeKey()] {
			ctor.removeParam(r.nodeKey())
		}
	}
}

// pruneCtorGroupParams removes constructor results that are still referenced in the GroupParams of
// constructors that consume those results.
func (dg *Graph) pruneCtorGroupParams(groups map[nodeKey]*Group) {
	for _, c := range dg.Ctors {
		var pruned []*Group
		for _, gp := range c.GroupParams {
			k := gp.nodeKey()
			if _, ok := groups[k]; ok {
				pruned = append(pruned, gp)
			}
		}
		c.GroupParams = pruned
	}
}

// pruneGroupResults removes results of the constructor argument that are still referenced in
// the Group object that contains that result. If a group no longer exists references to that
// should should be removed.
func (dg *Graph) pruneGroupResults(c *Ctor, groups map[nodeKey]*Group) {
	for _, r := range c.Results {
		k := r.nodeKey()
		if k.group == "" {
			continue
		}

		g, ok := groups[k]
		if ok {
			g.removeResult(r)
		}
	}
}

// String implements fmt.Stringer for Param.
func (p *Param) String() string {
	if p.Name != "" {
		return fmt.Sprintf("%v[name=%v]", p.Type.String(), p.Name)
	}
	return p.Type.String()
}

// String implements fmt.Stringer for Result.
func (r *Result) String() string {
	switch {
	case r.Name != "":
		return fmt.Sprintf("%v[name=%v]", r.Type.String(), r.Name)
	case r.Group != "":
		return fmt.Sprintf("%v[group=%v]%v", r.Type.String(), r.Group, r.GroupIndex)
	default:
		return r.Type.String()
	}
}

// String implements fmt.Stringer for Group.
func (g *Group) String() string {
	return fmt.Sprintf("[type=%v group=%v]", g.Type.String(), g.Name)
}

// Attributes composes and returns a string of the Result node's attributes.
func (r *Result) Attributes() string {
	switch {
	case r.Name != "":
		return fmt.Sprintf(`label=<%v<BR /><FONT POINT-SIZE="10">Name: %v</FONT>>`, r.Type, r.Name)
	case r.Group != "":
		return fmt.Sprintf(`label=<%v<BR /><FONT POINT-SIZE="10">Group: %v</FONT>>`, r.Type, r.Group)
	default:
		return fmt.Sprintf(`label=<%v>`, r.Type)
	}
}

// Attributes composes and returns a string of the Group node's attributes.
func (g *Group) Attributes() string {
	attr := fmt.Sprintf(`shape=diamond label=<%v<BR /><FONT POINT-SIZE="10">Group: %v</FONT>>`, g.Type, g.Name)
	if g.ErrorType != noError {
		attr += " color=" + g.ErrorType.Color()
	}
	return attr
}

// Color returns the color representation of each ErrorType.
func (s ErrorType) Color() string {
	switch s {
	case rootCause:
		return "red"
	case transitiveFailure:
		return "orange"
	default:
		return "black"
	}
}

func (dg *Graph) addRootCause(r *Result) {
	dg.Failed.RootCauses = append(dg.Failed.RootCauses, r)
}

func (dg *Graph) addTransitiveFailure(r *Result) {
	dg.Failed.TransitiveFailures = append(dg.Failed.TransitiveFailures, r)
}
