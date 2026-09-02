// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/internal"
	"go.yaml.in/yaml/v3"
)

type Reconciler[Obj any] interface {
	// Prune triggers an immediate pruning regardless of [PruneInterval].
	// Implemented as a select+send to a channel of size 1, so N concurrent
	// calls of this method may result in less than N full reconciliations.
	// This still requires the table to be fully initialized to have an effect.
	//
	// Primarily useful in tests, but may be of use when there's knowledge
	// that something has gone wrong in the reconciliation target and full
	// reconciliation is needed to recover.
	Prune()

	// WaitUntilReconciled blocks until the reconciler has processed all
	// table changes up to untilRevision. Returns the revision to which
	// objects have been attempted to be reconciled at least once, the lowest
	// revision of an object that failed to reconcile and ctx.Err() if the context
	// is cancelled.
	//
	// If you want to wait until objects have been successfully reconciled up to
	// a specific revision then this method should be called repeatedly until
	// both [revision] and [retryLowWatermark] are past the desired [untilRevision].
	WaitUntilReconciled(ctx context.Context, untilRevision statedb.Revision) (revision statedb.Revision, retryLowWatermark statedb.Revision, err error)
}

// Params are the reconciler dependencies that are independent of the
// use-case.
type Params struct {
	cell.In

	Log            *slog.Logger
	DB             *statedb.DB
	JobGroup       job.Group
	ModuleID       cell.FullModuleID
	DefaultMetrics Metrics `optional:"true"`
}

// Operations defines how to reconcile an object.
//
// Each operation is given a context that limits the lifetime of the operation
// and a ReadTxn to allow looking up referenced state.
type Operations[Obj any] interface {
	// Update the object in the target. If the operation is long-running it should
	// abort if context is cancelled. Should return an error if the operation fails.
	// The reconciler will retry the operation again at a later time, potentially
	// with a new version of the object. The operation should thus be idempotent.
	//
	// Update is used both for incremental and full reconciliation. Incremental
	// reconciliation is performed when the desired state is updated. A full
	// reconciliation is done periodically by calling 'Update' on all objects.
	//
	// The object handed to Update is a clone produced by Config.CloneObject
	// and thus Update can mutate the object. The mutations are only guaranteed
	// to be retained if the object has a single reconciler (one Status).
	Update(ctx context.Context, txn statedb.ReadTxn, revision statedb.Revision, obj Obj) error

	// Delete the object in the target. Same semantics as with Update.
	// Deleting a non-existing object is not an error and returns nil.
	Delete(context.Context, statedb.ReadTxn, statedb.Revision, Obj) error

	// Prune undesired state. It is given an iterator for the full set of
	// desired objects. The implementation should diff the desired state against
	// the realized state to find things to prune.
	// Invoked during full reconciliation before the individual objects are Update()'d.
	//
	// Unlike failed Update()'s a failed Prune() operation is not retried until
	// the next full reconciliation round.
	Prune(ctx context.Context, txn statedb.ReadTxn, objects iter.Seq2[Obj, statedb.Revision]) error
}

type BatchEntry[Obj any] struct {
	Object   Obj
	Revision statedb.Revision
	Result   error

	original Obj
}

type BatchOperations[Obj any] interface {
	UpdateBatch(ctx context.Context, txn statedb.ReadTxn, batch []BatchEntry[Obj])
	DeleteBatch(context.Context, statedb.ReadTxn, []BatchEntry[Obj])
}

// StatusKind marks the state of status.
//
// This is a struct for legacy reasons. This used to string, but to save on space
// this is now a uint8. By wrapping it into a struct we force the use-sites to
// use StatusKind.String() and makes it impossible to do string(foo.Status.Kind).
type StatusKind struct {
	kind uint8
}

var (
	StatusKindUnset      = StatusKind{0}
	StatusKindPending    = StatusKind{1}
	StatusKindRefreshing = StatusKind{2}
	StatusKindDone       = StatusKind{3}
	StatusKindError      = StatusKind{4}
)

var stringToStatusKind = map[string]StatusKind{
	"":           StatusKindUnset,
	"Done":       StatusKindDone,
	"Pending":    StatusKindPending,
	"Refreshing": StatusKindRefreshing,
	"Error":      StatusKindError,
}

var statusKindToString = map[StatusKind]string{
	StatusKindUnset:      "",
	StatusKindPending:    "Pending",
	StatusKindRefreshing: "Refreshing",
	StatusKindDone:       "Done",
	StatusKindError:      "Error",
}

func (s StatusKind) String() string {
	return statusKindToString[s]
}

func (s *StatusKind) UnmarshalJSON(b []byte) error {
	if len(b) < 2 && b[0] != '"' && b[len(b)-1] != '"' {
		return errors.New("expected quoted string")
	}
	b = b[1 : len(b)-1]
	*s = stringToStatusKind[string(b)]
	return nil
}

func (s StatusKind) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

func (s *StatusKind) UnmarshalYAML(value *yaml.Node) error {
	*s = stringToStatusKind[value.Value]
	return nil
}

func (s StatusKind) MarshalYAML() (any, error) {
	return s.String(), nil
}

var (
	pendingKey    = index.Key("P")
	refreshingKey = index.Key("R")
	doneKey       = index.Key("D")
	errorKey      = index.Key("E")
)

// Key implements an optimized construction of index.Key for StatusKind
// to avoid copying and allocation.
func (s StatusKind) Key() index.Key {
	switch s {
	case StatusKindPending:
		return pendingKey
	case StatusKindRefreshing:
		return refreshingKey
	case StatusKindDone:
		return doneKey
	case StatusKindError:
		return errorKey
	default:
		return index.Key("?")
	}
}

// Status is embedded into the reconcilable object. It allows
// inspecting per-object reconciliation status and waiting for
// the reconciler. Object may have multiple reconcilers and
// multiple reconciliation statuses.
type Status struct {
	UpdatedAt time.Time `json:"updated-at" yaml:"updated-at"`
	Error     *string   `json:"error,omitempty" yaml:"error,omitempty"`

	// id is a unique identifier for a pending object.
	// The reconciler uses this to compare whether the object
	// has really changed when committing the resulting status.
	// This allows multiple reconcilers to exist for a single
	// object without repeating work when status is updated.
	ID   uint64     `json:"id,omitempty" yaml:"id,omitempty"`
	Kind StatusKind `json:"kind" yaml:"kind"`
}

func (s Status) IsPendingOrRefreshing() bool {
	return s.Kind == StatusKindPending || s.Kind == StatusKindRefreshing
}

func (s Status) String() string {
	if s.Kind == StatusKindError {
		return fmt.Sprintf("Error: %s (%s ago)", s.GetError(), internal.PrettySince(s.UpdatedAt))
	}
	return fmt.Sprintf("%s (%s ago)", s.Kind, internal.PrettySince(s.UpdatedAt))
}

func (s Status) GetError() string {
	if s.Error == nil {
		return ""
	}
	return *s.Error
}

var idGen atomic.Uint64

func nextID() uint64 {
	return idGen.Add(1)
}

// StatusPending constructs the status for marking the object as
// requiring reconciliation. The reconciler will perform the
// Update operation and on success transition to Done status, or
// on failure to Error status.
func StatusPending() Status {
	return Status{
		Kind:      StatusKindPending,
		UpdatedAt: time.Now(),
		Error:     nil,
		ID:        nextID(),
	}
}

// StatusRefreshing constructs the status for marking the object as
// requiring refreshing. The reconciler will perform the
// Update operation and on success transition to Done status, or
// on failure to Error status.
//
// This is distinct from the Pending status in order to give a hint
// to the Update operation that this is a refresh of the object and
// should be forced.
func StatusRefreshing() Status {
	return Status{
		Kind:      StatusKindRefreshing,
		UpdatedAt: time.Now(),
		Error:     nil,
		ID:        nextID(),
	}
}

// StatusDone constructs the status that marks the object as
// reconciled.
func StatusDone() Status {
	return Status{
		Kind:      StatusKindDone,
		UpdatedAt: time.Now(),
		Error:     nil,
		ID:        nextID(),
	}
}

// statusError constructs the status that marks the object
// as failed to be reconciled.
func StatusError(err error) Status {
	errStr := "<nil>"
	if err != nil {
		errStr = err.Error()
	}
	return Status{
		Kind:      StatusKindError,
		UpdatedAt: time.Now(),
		Error:     &errStr,
		ID:        nextID(),
	}
}

// StatusSet is a set of named statuses. This allows an object to be
// reconciled by multiple reconcilers, whether or not their names are known
// up front.
type StatusSet struct {
	id        uint64
	updatedAt time.Time
	statuses  []namedStatus
}

type namedStatus struct {
	Status
	name string
}

func (s StatusSet) find(name string) (int, bool) {
	return slices.BinarySearchFunc(
		s.statuses,
		name,
		func(status namedStatus, name string) int {
			return cmp.Compare(status.name, name)
		})
}

func NewStatusSet() StatusSet {
	return StatusSet{
		id:        nextID(),
		updatedAt: time.Now(),
		statuses:  nil,
	}
}

// Pending returns a new pending status set with an optional default set of
// reconciler names.
//
// Reconciler names from previous statuses are merged with the
// given optional set of names.
func (s StatusSet) Pending(names ...string) StatusSet {
	// Generate a new id. This lets an individual reconciler
	// differentiate between the status changing in an object
	// versus the data itself, which is needed when the reconciler
	// writes back the reconciliation status and the object has
	// changed.
	s.id = nextID()
	s.updatedAt = time.Now()

	pending := Status{
		Kind:      StatusKindPending,
		UpdatedAt: s.updatedAt,
		ID:        s.id,
	}

	s.statuses = slices.Clone(s.statuses)
	for i := range s.statuses {
		s.statuses[i].Status = pending
	}

	for _, name := range names {
		i, found := s.find(name)
		if !found {
			s.statuses = slices.Insert(
				s.statuses, i, namedStatus{Status: pending, name: name})
		}
	}
	return s
}

func (s StatusSet) String() string {
	if len(s.statuses) == 0 {
		return "Pending"
	}

	var updatedAt time.Time
	done := []string{}
	pending := []string{}
	errored := []string{}

	for _, status := range s.statuses {
		if status.UpdatedAt.After(updatedAt) {
			updatedAt = status.UpdatedAt
		}
		switch status.Kind {
		case StatusKindDone:
			done = append(done, status.name)
		case StatusKindError:
			errored = append(errored, status.name+" ("+status.GetError()+")")
		default:
			pending = append(pending, status.name)
		}
	}
	var b strings.Builder
	if len(errored) > 0 {
		b.WriteString("Errored: ")
		b.WriteString(strings.Join(errored, " "))
	}
	if len(pending) > 0 {
		if b.Len() > 0 {
			b.WriteString(", ")
		}
		b.WriteString("Pending: ")
		b.WriteString(strings.Join(pending, " "))
	}
	if len(done) > 0 {
		if b.Len() > 0 {
			b.WriteString(", ")
		}
		b.WriteString("Done: ")
		b.WriteString(strings.Join(done, " "))
	}
	b.WriteString(" (")
	b.WriteString(internal.PrettySince(updatedAt))
	b.WriteString(" ago)")
	return b.String()
}

// Set the reconciliation status of the named reconciler.
// Use this to implement 'SetObjectStatus' for your reconciler.
func (s StatusSet) Set(name string, status Status) StatusSet {
	i, found := s.find(name)
	if found {
		s.statuses = slices.Clone(s.statuses)
		s.statuses[i].Status = status
	} else {
		statuses := make([]namedStatus, len(s.statuses)+1)
		copy(statuses, s.statuses[:i])
		statuses[i] = namedStatus{Status: status, name: name}
		copy(statuses[i+1:], s.statuses[i:])
		s.statuses = statuses
	}
	return s
}

// Get returns the status for the named reconciler.
// Use this to implement 'GetObjectStatus' for your reconciler.
// If this reconciler is new the status is pending.
func (s StatusSet) Get(name string) Status {
	i, found := s.find(name)
	if !found {
		return Status{
			Kind:      StatusKindPending,
			UpdatedAt: s.updatedAt,
			ID:        s.id,
		}
	}
	return s.statuses[i].Status
}

// Delete returns a new status set without the named reconciler.
// A subsequent Pending call will not mark the reconciler pending unless its
// name is passed to Pending again.
func (s StatusSet) Delete(name string) StatusSet {
	i, found := s.find(name)
	if !found {
		return s
	}

	statuses := make([]namedStatus, len(s.statuses)-1)
	copy(statuses, s.statuses[:i])
	copy(statuses[i:], s.statuses[i+1:])
	s.statuses = statuses
	return s
}

// All returns an iterator for all reconciler statuses.
func (s *StatusSet) All() iter.Seq2[string, Status] {
	return func(yield func(name string, status Status) bool) {
		for _, ns := range s.statuses {
			if !yield(ns.name, ns.Status) {
				break
			}
		}
	}
}

// IsPending returns true if any of the reconcilers are still pending
// or refreshing.
func (s *StatusSet) IsPendingOrRefreshing() bool {
	for _, ns := range s.statuses {
		if ns.Status.IsPendingOrRefreshing() {
			return true
		}
	}
	return false
}

// IsDone returns true if all reconcilers are done.
func (s *StatusSet) IsDone() bool {
	for _, ns := range s.statuses {
		if ns.Status.Kind != StatusKindDone {
			return false
		}
	}
	return true
}

func (s *StatusSet) UnmarshalJSON(data []byte) error {
	m := map[string]Status{}
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	s.statuses = make([]namedStatus, 0, len(m))
	for name, status := range m {
		s.statuses = append(s.statuses, namedStatus{status, name})
	}
	slices.SortFunc(s.statuses,
		func(a, b namedStatus) int { return cmp.Compare(a.name, b.name) })
	return nil
}

// MarshalJSON marshals the StatusSet as a map[string]Status.
// It carries enough information over to be able to implement String()
// so this can be used to implement the TableRow() method.
func (s StatusSet) MarshalJSON() ([]byte, error) {
	return json.Marshal(maps.Collect(s.All()))
}
