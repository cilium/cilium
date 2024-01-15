// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package health

import (
	"runtime"
	"sync/atomic"

	"github.com/cilium/cilium/pkg/hive/cell"
)

// Scope provides a node in the structured health reporter tree that is
// serves only as a parent for other nodes (scopes or reporters), and is
// used to group related reporters together.
type Scope interface {
	// Name returns the name of the scope.
	Name() string

	// Close removes the scope from the tree, and stops all reporters under this scope.
	// Using a reporter that is under this scope after Close has been called will result
	// in a noop update and warning log.
	// Thus it is preferable for all reporters to be Stopped first, before calling Close.
	Close()

	scope() *subReporter
}

// GetSubScope creates a new reporter scope under the given parent scope.
// This creates a new node in the structured health reporter tree, and any calls
// to GetSubScope or GetHealthReporter from the returned scope will return a child node
// of this reporter tree.
//
// GetSubScope can be chained together to create various levels of sub reporters.
//
// Example:
//
// 1. Init root scope (note: this is provided to modules automatically).
// root := rootScope(hr)
//
//	root
//
// 2. Create endpoint-manager subscope, and reporter under that scope (with ok!)
//
// endpointManagerScope := GetSubScope(root, "endpoint-manager")
// GetHealthReporter(endpointManagerScope, "endpoint-000").OK("it works!")
//
//	 root(OK)
//		└── scope(endpoint-manager, OK)
//			└── reporter(endpoint-000, OK)
//
// 3. Create another reporter under that scope with degraded
// GetHealthReporter(endpointManagerScope, "endpoint-000").Degraded("oh no!")
//
//	 root(Degraded)
//		└── scope(endpoint-manager, Degraded)
//			└── reporter(endpoint-000, OK)
//			└── reporter(endpoint-000, Degraded)
//
// 4. Close the endpoint-manager scope
// s.Close()
//
//	root(OK) 	// status has been reported, but we no longer have any degraded status
//				// default to ok status.
func GetSubScope(parent Scope, name string, opts ...ReporterOpt) Scope {
	if parent == nil {
		return nil
	}
	s := createSubScope(parent, name)
	for _, opt := range opts {
		opt(s.scope())
	}
	return s
}

func DecorateModuleScope() cell.Cell {
	return cell.Decorate(func(parent Scope, id cell.ModuleID) Scope {
		return createSubScope(parent, string(id))
	})
}

type ReporterOpt func(r *subReporter)

func WithFeature(feature Feature) ReporterOpt {
	return func(r *subReporter) {
		r.feature = feature
	}
}

// GetHealthReporter creates a new reporter under the given parent scope.
func GetHealthReporter(parent Scope, name string, opts ...ReporterOpt) HealthReporter {
	if parent == nil {
		return &noopReporter{}
	}
	r := getSubReporter(parent, name, true)
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// rootScope always
func rootScope(id cell.FullModuleID, hr statusNodeReporter) *scope {
	r := &subReporter{
		base: &subreporterBase{},
		path: NewIdentifier(id),
	}
	r.base.hr.Store(&hr)
	// create root node, required in case reporters are created without any subscopes.
	return &scope{subReporter: r}
}

type scope struct {
	*subReporter
}

func (s *scope) Close() {
	// TODO
}

func (s *scope) scope() *subReporter {
	return s.subReporter
}

func (s *scope) Name() string {
	return s.path.component()
}

// When a scope is orphaned and garbage collected, we want to remove it from the tree if
// the following condition is met:
//  1. All scopes under this scope also have no references.
//  2. There are no reporters under this scope (reporters are always removed immediately
//     after they are stopped).
//
// This means that scopes are only kept in the tree if they either have referenced subscopes,
// or if they have reporters under them.
// If a scope is orphaned, and all it's children are orphaned, and it has no reporter children
// then it is impossible for any new reporters to be created under this scope.
//
// Because reporters are only removed when they are explicitly stopped, this means that if a
// reporter node emits a ok/degraded status and then is orphaned.
// This is ok, because we're primarily interested in ensure that ephemerally created scopes that
// are never reported upon and then lost do not grow the tree indefinitely.
func createSubScope(parent Scope, name string) *scope {
	s := &scope{
		subReporter: getSubReporter(parent, name, false),
	}
	runtime.SetFinalizer(s, func(s *scope) {
		// TODO: Remove updates that are not a prefix to any other updates.
		// We can do this with a prefix check, but we'll want to batch these up.

	})
	return s
}

func getSubReporter(parent Scope, name string, isReporter bool) *subReporter {
	return scopeFromParent(parent, name, isReporter)
}

func scopeFromParent(parent Scope, name string, isReporter bool) *subReporter {
	return &subReporter{
		base: parent.scope().base,
		path: parent.scope().path.withSubComponent(name),
	}
}

// subreporterBase is the base implementation of a structured health reporter.
// Each node in a reporter tree (i.e. for each cell.Module) has a pointer to
// the single subreporterBase.
// subreporterBase maintains the tree structure, as well as is responsible for
// realizing the status tree, and emitting the status to the module HealthReporter.
type subreporterBase struct {
	// Module level health reporter, all realized status is emitted to this reporter.
	hr atomic.Pointer[statusNodeReporter]
}

// subReporter represents both reporter "leaf" nodes and intermediate
// "scope" nodes.
// subReporter only has a pointer to the base, thus copying a subReporter
// by value yields the same "reporter".
//
// Note: For the V2 implementation of this, we will still pass around a reporter
// scope which will allow modules to derive subreporters or subscopes.
// However, this will now be lock free, variables in the reporter scope must
// be immutable or use atomics after creation to ensure thread safety.
type subReporter struct {
	base    *subreporterBase
	path    Identifier
	feature Feature
}

func (s *subReporter) OK(message string) {
	hr := s.base.hr.Load()
	if hr == nil {
		return
	}
	(*hr).upsertStatus(s.path, StatusV2{
		ID:      s.path,
		Level:   StatusOK,
		Message: message,
	})
}

func (s *subReporter) Degraded(message string, err error) {
	hr := s.base.hr.Load()
	if hr == nil {
		return
	}
	(*hr).upsertStatus(s.path, StatusV2{
		ID:      s.path,
		Level:   StatusDegraded,
		Message: message,
	})
}

// Stopped marks the subreporter as stopped by removing it from the tree.
// Stopped reporters can immediately be removed from the tree, since they do
// not have any children.
func (s *subReporter) Stopped(message string) {
	hr := s.base.hr.Load()
	if hr == nil {
		return
	}
	(*hr).removeStatusTree(s.path)
}

type noopReporter struct{}

func (s *noopReporter) OK(message string)                  {}
func (s *noopReporter) Degraded(message string, err error) {}
func (s *noopReporter) Stopped(message string)             {}
