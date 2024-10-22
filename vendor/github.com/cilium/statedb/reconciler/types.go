// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
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
}

// Params are the reconciler dependencies that are independent of the
// use-case.
type Params struct {
	cell.In

	Lifecycle      cell.Lifecycle
	Log            *slog.Logger
	DB             *statedb.DB
	Jobs           job.Registry
	ModuleID       cell.FullModuleID
	Health         cell.Health
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
	Update(ctx context.Context, txn statedb.ReadTxn, obj Obj) error

	// Delete the object in the target. Same semantics as with Update.
	// Deleting a non-existing object is not an error and returns nil.
	Delete(context.Context, statedb.ReadTxn, Obj) error

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

type StatusKind string

const (
	StatusKindPending    StatusKind = "Pending"
	StatusKindRefreshing StatusKind = "Refreshing"
	StatusKindDone       StatusKind = "Done"
	StatusKindError      StatusKind = "Error"
)

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
	}
	panic("BUG: unmatched StatusKind")
}

// Status is embedded into the reconcilable object. It allows
// inspecting per-object reconciliation status and waiting for
// the reconciler. Object may have multiple reconcilers and
// multiple reconciliation statuses.
type Status struct {
	Kind      StatusKind
	UpdatedAt time.Time
	Error     string

	// id is a unique identifier for a pending object.
	// The reconciler uses this to compare whether the object
	// has really changed when committing the resulting status.
	// This allows multiple reconcilers to exist for a single
	// object without repeating work when status is updated.
	id uint64
}

func (s Status) IsPendingOrRefreshing() bool {
	return s.Kind == StatusKindPending || s.Kind == StatusKindRefreshing
}

func (s Status) String() string {
	if s.Kind == StatusKindError {
		return fmt.Sprintf("Error: %s (%s ago)", s.Error, prettySince(s.UpdatedAt))
	}
	return fmt.Sprintf("%s (%s ago)", s.Kind, prettySince(s.UpdatedAt))
}

func prettySince(t time.Time) string {
	ago := float64(time.Now().Sub(t)) / float64(time.Millisecond)
	// millis
	if ago < 1000.0 {
		return fmt.Sprintf("%.1fms", ago)
	}
	// secs
	ago /= 1000.0
	if ago < 60.0 {
		return fmt.Sprintf("%.1fs", ago)
	}
	// mins
	ago /= 60.0
	if ago < 60.0 {
		return fmt.Sprintf("%.1fm", ago)
	}
	// hours
	ago /= 60.0
	return fmt.Sprintf("%.1fh", ago)
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
		Error:     "",
		id:        nextID(),
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
		Error:     "",
	}
}

// StatusDone constructs the status that marks the object as
// reconciled.
func StatusDone() Status {
	return Status{
		Kind:      StatusKindDone,
		UpdatedAt: time.Now(),
		Error:     "",
	}
}

// statusError constructs the status that marks the object
// as failed to be reconciled.
func StatusError(err error) Status {
	return Status{
		Kind:      StatusKindError,
		UpdatedAt: time.Now(),
		Error:     err.Error(),
	}
}

// StatusSet is a set of named statuses. This allows for the use of
// multiple reconcilers per object when the reconcilers are not known
// up front.
type StatusSet struct {
	id        uint64
	createdAt time.Time
	statuses  []namedStatus
}

type namedStatus struct {
	Status
	name string
}

func NewStatusSet() StatusSet {
	return StatusSet{
		id:        nextID(),
		createdAt: time.Now(),
		statuses:  nil,
	}
}

// Pending returns a new pending status set.
// The names of reconcilers are reused to be able to show which
// are still pending.
func (s StatusSet) Pending() StatusSet {
	// Generate a new id. This lets an individual reconciler
	// differentiate between the status changing in an object
	// versus the data itself, which is needed when the reconciler
	// writes back the reconciliation status and the object has
	// changed.
	s.id = nextID()
	s.createdAt = time.Now()

	s.statuses = slices.Clone(s.statuses)
	for i := range s.statuses {
		s.statuses[i].Kind = StatusKindPending
		s.statuses[i].id = s.id
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
			errored = append(errored, status.name+" ("+status.Error+")")
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
	b.WriteString(prettySince(updatedAt))
	b.WriteString(" ago)")
	return b.String()
}

// Set the reconcilation status of the named reconciler.
// Use this to implement 'SetObjectStatus' for your reconciler.
func (s StatusSet) Set(name string, status Status) StatusSet {
	idx := slices.IndexFunc(
		s.statuses,
		func(st namedStatus) bool { return st.name == name })

	s.statuses = slices.Clone(s.statuses)
	if idx >= 0 {
		s.statuses[idx] = namedStatus{status, name}
	} else {
		s.statuses = append(s.statuses, namedStatus{status, name})
		slices.SortFunc(s.statuses,
			func(a, b namedStatus) int { return cmp.Compare(a.name, b.name) })
	}
	return s
}

// Get returns the status for the named reconciler.
// Use this to implement 'GetObjectStatus' for your reconciler.
// If this reconciler is new the status is pending.
func (s StatusSet) Get(name string) Status {
	idx := slices.IndexFunc(
		s.statuses,
		func(st namedStatus) bool { return st.name == name })
	if idx < 0 {
		return Status{
			Kind:      StatusKindPending,
			UpdatedAt: s.createdAt,
			id:        s.id,
		}
	}
	return s.statuses[idx].Status
}

func (s StatusSet) All() map[string]Status {
	m := make(map[string]Status, len(s.statuses))
	for _, ns := range s.statuses {
		m[ns.name] = ns.Status
	}
	return m
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
	return json.Marshal(s.All())
}
