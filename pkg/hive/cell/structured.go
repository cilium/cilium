// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"text/tabwriter"
	"time"

	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/lock"

	"golang.org/x/exp/maps"
	"k8s.io/apimachinery/pkg/util/duration"
	"k8s.io/apimachinery/pkg/util/sets"
)

type children sets.Set[string]

// reporterMinTimeout is the minimum time between status realizations, this
// prevents excessive reporter tree walks which hold the lock.
// This also acts as a rate limiter for status updates, if a update is not realized
// because the minimum timeout has not elapsed, it will eventually be realized by
// a periodic wakeup of the same interval.
//
// HealthReporting is not intendeds to capture high frequency events, but rather provide
// a structured view of the health of the system.
var reporterMinTimeout = time.Millisecond * 500

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

	// Realize schedules an immediate realization of the status.
	Realize()

	scope() *subReporter
}

func GetSubScope(parent Scope, name string) Scope {
	if parent == nil {
		return &wipHealthV2Shim{noOpReporter{}}
	}
	shim := parent.(*wipHealthV2Shim)
	rs := shim.NewScope(name)
	return &wipHealthV2Shim{rs}
}

// GetHealthReporter creates a new reporter under the given parent scope.
func GetHealthReporter(parent Scope, name string) HealthReporter {
	if parent == nil {
		return &noOpReporter{}
	}
	shim := parent.(*wipHealthV2Shim)
	if shim.Health == nil {
		return &noOpReporter{}
	}
	rs := shim.NewScope(name)
	return &wipHealthV2Shim{rs}
}

// TestScope exposes creating a root scope for testing purposes only.
// Deprecated/TODO: This will be replaced by cilium/hive "simple" health implementation
// following switching to external library.
func TestScope() Scope {
	return &wipHealthV2Shim{}
}

// TestScope exposes creating a root scope from a health provider for testing purposes only.
func TestScopeFromProvider(moduleID FullModuleID, hp Health) Scope {
	s := rootScope(moduleID, hp.forModule(moduleID))
	s.start()
	return s
}

func rootScope(id FullModuleID, hr statusNodeReporter) *scope {
	r := &subReporter{
		base: &subreporterBase{
			hr:           hr,
			idToChildren: map[string]children{},
			nodes:        map[string]*node{},
			wakeup:       make(chan struct{}, 16),
		},
	}
	// create root node, required in case reporters are created without any subscopes.
	r.id = r.base.addChild("", id.String(), false)
	r.base.rootID = r.id

	// Realize walks the tree and creates a updated status for the reporter.
	// Because this is blocking and can be expensive, we have a reconcile loop
	// that only performs this if the revision has changed.
	realize := func() {
		if r.base.stopped {
			return
		}
		statusTree := r.base.getStatusTreeLocked(r.base.rootID)
		if r.base.stopped {
			r.base.hr.setStatus(statusTree)
			return
		}
		if r.base.revision.Load() == 0 {
			return
		}
		r.base.hr.setStatus(statusTree)
	}

	r.scheduleRealize = func() {
		r.base.revision.Add(1)
		r.base.wakeup <- struct{}{}
	}
	r.realizeSync = realize

	return &scope{subReporter: r}
}

func (r *scope) start() {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		var rev uint64
		var lastUpdate time.Time
		for {
			select {
			case <-inctimer.After(reporterMinTimeout):
			case <-r.base.wakeup:
			case <-ctx.Done():
			}
			if rev < r.base.revision.Load() && time.Since(lastUpdate) > reporterMinTimeout {
				rev = r.base.revision.Load()
				r.base.Lock()
				r.realizeSync()
				r.base.Unlock()
				lastUpdate = time.Now()
			}
			if ctx.Err() != nil {
				return
			}
		}
	}()
	r.closeReconciler = cancel
}

type scope struct {
	*subReporter
}

func (s *scope) Close() {
	s.base.Lock()
	s.base.removeRefLocked(s.id)
	s.base.removeTreeLocked(s.id)
	s.base.Unlock()
	s.scheduleRealize()
}

func (s *scope) Realize() {
	s.base.Lock()
	s.realizeSync()
	s.base.Unlock()
}

func (s *scope) scope() *subReporter {
	return s.subReporter
}

func (s *scope) Name() string {
	return s.name
}

// subreporterBase is the base implementation of a structured health reporter.
// Each node in a reporter tree (i.e. for each cell.Module) has a pointer to
// the single subreporterBase.
// subreporterBase maintains the tree structure, as well as is responsible for
// realizing the status tree, and emitting the status to the module HealthReporter.
type subreporterBase struct {
	lock.Mutex

	// Module level health reporter, all realized status is emitted to this reporter.
	hr statusNodeReporter

	// idToChildren is the adjacency map of parentID to children IDs.
	idToChildren map[string]children
	nodes        map[string]*node

	// rootID is the root node of the tree, it should always exist in idToChildren and nodes.
	rootID string

	stopped bool

	// Variables used for realization loop, because realization involves traversing the tree
	// we only perform this when the revision has changed.
	revision atomic.Uint64
	counter  atomic.Int32
	wakeup   chan struct{}
}

func (s *subreporterBase) addNode(n *node) {
	if _, ok := s.idToChildren[n.parentID]; !ok {
		s.idToChildren[n.parentID] = children{}
	}
	s.idToChildren[n.parentID][n.id] = struct{}{}
	s.idToChildren[n.id] = children{}
	s.nodes[n.id] = n
}

func (s *subreporterBase) addChild(pid string, name string, isReporter bool) string {
	id := strconv.Itoa(int(s.counter.Add(1))) + "-" + name
	s.addNode(&node{
		id:       id,
		parentID: pid,
		count:    1,
		nodeUpdate: nodeUpdate{
			Level:     StatusUnknown,
			Timestamp: time.Now(),
		},
		name:       name,
		isReporter: isReporter,
		refs:       1,
	})
	return id
}

var errReporterStopped = errors.New("reporter has been stopped")

func (s *subreporterBase) setStatus(id string, level Level, message string, err error) error {
	s.Lock()
	defer s.Unlock()

	if s.stopped {
		return fmt.Errorf("reporter tree %s has been stopped", id)
	}

	if _, ok := s.nodes[id]; !ok {
		return fmt.Errorf("could not set status for reporter %s: %w", id, errReporterStopped)
	}

	n := s.nodes[id]

	if n.Level == level && n.Message == message {
		n.count++
	} else {
		n.count = 1
	}

	n.Level = level
	n.Message = message
	n.Error = err
	return nil
}

func (s *subreporterBase) removeTreeLocked(rid string) {
	for child := range s.idToChildren[rid] {
		s.removeTreeLocked(child)
	}
	// Safely remove parents reference to this node.
	if _, ok := s.nodes[rid]; ok {
		pid := s.nodes[rid].parentID
		delete(s.idToChildren[pid], rid)
	}
	delete(s.idToChildren, rid)
	delete(s.nodes, rid)
}

// StatusNode is a model struct for a status tree realization result.
// It is created upon status tree realization, for now it is only used for
// for generating a plaintext representation of the status tree.
// In the future we will want to use this to generate a structured JSON representation
// of the status tree.
type StatusNode struct {
	ID              string        `json:"id"`
	LastLevel       Level         `json:"level,omitempty"`
	Name            string        `json:"name"`
	Message         string        `json:"message,omitempty"`
	UpdateTimestamp time.Time     `json:"timestamp"`
	Count           int           `json:"count"`
	SubStatuses     []*StatusNode `json:"sub_statuses,omitempty"`
	Error           string        `json:"error,omitempty"`
}

var _ Update = (*StatusNode)(nil)

func (s *StatusNode) Level() Level {
	return s.LastLevel
}

func (s *StatusNode) Timestamp() time.Time {
	return s.UpdateTimestamp
}

func (s *StatusNode) JSON() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

func (s *StatusNode) allOk() bool {
	return s.LastLevel == StatusOK
}

func (s *StatusNode) writeTo(w io.Writer, d int) {
	if len(s.SubStatuses) == 0 {
		since := "never"
		if !s.UpdateTimestamp.IsZero() {
			since = duration.HumanDuration(time.Since(s.UpdateTimestamp)) + " ago"
		}
		fmt.Fprintf(w, "%s%s\t%s\t%s\t%s\t(x%d)\n", strings.Repeat("\t", d), s.Name, s.LastLevel, s.Message, since, s.Count)
	} else {
		fmt.Fprintf(w, "%s%s\n", strings.Repeat("\t", d), s.Name)
		for _, ss := range s.SubStatuses {
			ss.writeTo(w, d+1)
		}
	}
}

func (s *StatusNode) StringIndent(ident int) string {
	if s == nil {
		return ""
	}
	buf := bytes.NewBuffer(nil)
	w := tabwriter.NewWriter(buf, 0, 0, 1, ' ', 0)
	s.writeTo(w, ident)
	w.Flush()
	return buf.String()
}

func (s *StatusNode) String() string {
	return s.Message
}

func (s *subreporterBase) getStatusTreeLocked(nid string) *StatusNode {
	if children, ok := s.idToChildren[nid]; ok {
		rn := s.nodes[nid]
		n := &StatusNode{
			ID:              nid,
			Message:         rn.Message,
			Name:            rn.name,
			UpdateTimestamp: rn.Timestamp,
			Count:           rn.count,
		}
		if err := rn.Error; err != nil {
			n.Error = err.Error()
		}
		allok := true
		childIDs := maps.Keys(children)
		sort.Strings(childIDs)
		for _, child := range childIDs {
			cn := s.getStatusTreeLocked(child)
			if cn == nil {
				log.Errorf("failed to get status for node %s", child)
				continue
			}
			n.SubStatuses = append(n.SubStatuses, cn)
			if !cn.allOk() {
				allok = false
			}
		}
		// If this is not a leaf and all children are ok then report ok.
		// case 1: Non-reporter, has no children, should be ok?
		// case 2: Non-reporter, has children, defer down to children.
		if rn.isReporter {
			n.LastLevel = rn.Level
		} else {
			if allok {
				n.LastLevel = StatusOK
			} else {
				n.LastLevel = StatusDegraded
			}
		}

		return n
	}
	return nil
}

type node struct {
	id         string
	name       string
	parentID   string
	isReporter bool
	count      int
	refs       int
	Message    string
	Error      error
	nodeUpdate
}
type nodeUpdate struct {
	Level
	Timestamp time.Time
}

func (b *subreporterBase) removeRefLocked(id string) {
	if _, ok := b.nodes[id]; ok {
		if b.nodes[id].refs > 0 {
			b.nodes[id].refs--
		}
	}
}

// subReporter represents both reporter "leaf" nodes and intermediate
// "scope" nodes.
// subReporter only has a pointer to the base, thus copying a subReporter
// by value yields the same "reporter".
type subReporter struct {
	base *subreporterBase
	// Triggers realization asynchronously, should not hold lock when calling.
	scheduleRealize func()
	// Triggers realization synchronously, base lock must be held when calling.
	// Use for final status flushes.
	realizeSync func()

	closeReconciler func()
	id              string
	name            string
}

const logReporterID = "reporterID"

func (s *subReporter) OK(message string) {
	if err := s.base.setStatus(s.id, StatusOK, message, nil); err != nil {
		if errors.Is(err, errReporterStopped) {
			log.WithError(err).WithField(logReporterID, s.id).Debug("could not set OK status on subreporter")
		} else {
			log.WithError(err).WithField(logReporterID, s.id).Warn("could not set OK status on subreporter")
		}
		return
	}

	s.scheduleRealize()
}

func (s *subReporter) Degraded(message string, err error) {
	if err := s.base.setStatus(s.id, StatusDegraded, message, err); err != nil {
		if errors.Is(err, errReporterStopped) {
			log.WithError(err).WithField(logReporterID, s.id).Debug("could not set degraded status on subreporter")
		} else {
			log.WithError(err).WithField(logReporterID, s.id).Warn("could not set degraded status on subreporter")
		}
		return
	}
	s.scheduleRealize()
}

// Stopped marks the subreporter as stopped by removing it from the tree.
// Stopped reporters can immediately be removed from the tree, since they do
// not have any children.
func (s *subReporter) Stopped(message string) {
	s.base.Lock()
	s.base.removeTreeLocked(s.id)
	s.base.Unlock()
	s.scheduleRealize()
}
