// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/time/rate"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
)

type Reconciler[Obj any] interface {
	// TriggerFullReconciliation triggers an immediate full reconciliation,
	// e.g. Prune() of unknown objects and Update() of all objects.
	// Implemented as a select+send to a channel of size 1, so N concurrent
	// calls of this method may result in less than N full reconciliations.
	//
	// Primarily useful in tests, but may be of use when there's knowledge
	// that something has gone wrong in the reconciliation target and full
	// reconciliation is needed to recover.
	TriggerFullReconciliation()
}

type Config[Obj any] struct {
	// Table to reconcile.
	Table statedb.RWTable[Obj]

	// Metrics to use with this reconciler. The metrics capture the duration
	// of operations during incremental and full reconcilation and the errors
	// that occur during either.
	//
	// If nil, then the default metrics are used via Params.
	// A simple implementation of metrics based on the expvar package come
	// with the reconciler and a custom one can be used by implementing the
	// Metrics interface.
	Metrics Metrics

	// FullReconcilationInterval is the amount of time to wait between full
	// reconciliation rounds. A full reconciliation is Prune() of unexpected
	// objects and Update() of all objects. With full reconciliation we're
	// resilient towards outside changes. If FullReconcilationInterval is
	// 0 then full reconciliation is disabled.
	FullReconcilationInterval time.Duration

	// RetryBackoffMinDuration is the minimum amount of time to wait before
	// retrying a failed Update() or Delete() operation on an object.
	// The retry wait time for an object will increase exponentially on
	// subsequent failures until RetryBackoffMaxDuration is reached.
	RetryBackoffMinDuration time.Duration

	// RetryBackoffMaxDuration is the maximum amount of time to wait before
	// retrying.
	RetryBackoffMaxDuration time.Duration

	// IncrementalRoundSize is the maximum number objects to reconcile during
	// incremental reconciliation before updating status and refreshing the
	// statedb snapshot. This should be tuned based on the cost of each operation
	// and the rate of expected changes so that health and per-object status
	// updates are not delayed too much. If in doubt, use a value between 100-1000.
	IncrementalRoundSize int

	// GetObjectStatus returns the reconciliation status for the object.
	GetObjectStatus func(Obj) Status

	// SetObjectStatus sets the reconciliation status for the object.
	// This is called with a copy of the object returned by CloneObject.
	SetObjectStatus func(Obj, Status) Obj

	// CloneObject returns a shallow copy of the object. This is used to
	// make it possible for the reconciliation operations to mutate
	// the object (to for example provide additional information that the
	// reconciliation produces) and to be able to set the reconciliation
	// status after the reconciliation.
	CloneObject func(Obj) Obj

	// RateLimiter is optional and if set will use the limiter to wait between
	// reconciliation rounds. This allows trading latency with throughput by
	// waiting longer to collect a batch of objects to reconcile.
	RateLimiter *rate.Limiter

	// Operations defines how an object is reconciled.
	Operations Operations[Obj]

	// BatchOperations is optional and if provided these are used instead of normal operations.
	BatchOperations BatchOperations[Obj]
}

func (cfg Config[Obj]) validate() error {
	if cfg.Table == nil {
		return fmt.Errorf("%T.Table cannot be nil", cfg)
	}
	if cfg.GetObjectStatus == nil {
		return fmt.Errorf("%T.GetObjectStatus cannot be nil", cfg)
	}
	if cfg.SetObjectStatus == nil {
		return fmt.Errorf("%T.SetObjectStatus cannot be nil", cfg)
	}
	if cfg.CloneObject == nil {
		return fmt.Errorf("%T.CloneObject cannot be nil", cfg)
	}
	if cfg.IncrementalRoundSize <= 0 {
		return fmt.Errorf("%T.IncrementalBatchSize needs to be >0", cfg)
	}
	if cfg.FullReconcilationInterval < 0 {
		return fmt.Errorf("%T.FullReconcilationInterval must be >=0", cfg)
	}
	if cfg.RetryBackoffMaxDuration <= 0 {
		return fmt.Errorf("%T.RetryBackoffMaxDuration must be >0", cfg)
	}
	if cfg.RetryBackoffMinDuration <= 0 {
		return fmt.Errorf("%T.RetryBackoffMinDuration must be >0", cfg)
	}
	if cfg.Operations == nil {
		return fmt.Errorf("%T.Operations must be defined", cfg)
	}
	return nil
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
	// and thus Update can mutate the object.
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
	Prune(context.Context, statedb.ReadTxn, statedb.Iterator[Obj]) error
}

type BatchEntry[Obj any] struct {
	Object   Obj
	Revision statedb.Revision
	Result   error
}

type BatchOperations[Obj any] interface {
	UpdateBatch(ctx context.Context, txn statedb.ReadTxn, batch []BatchEntry[Obj])
	DeleteBatch(context.Context, statedb.ReadTxn, []BatchEntry[Obj])
}

type StatusKind string

const (
	StatusKindPending StatusKind = "Pending"
	StatusKindDone    StatusKind = "Done"
	StatusKindError   StatusKind = "Error"
)

// Key implements an optimized construction of index.Key for StatusKind
// to avoid copying and allocation.
func (s StatusKind) Key() index.Key {
	switch s {
	case StatusKindPending:
		return index.Key("P")
	case StatusKindDone:
		return index.Key("D")
	case StatusKindError:
		return index.Key("E")
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

// StatusPending constructs the status for marking the object as
// requiring reconciliation. The reconciler will perform the
// Update operation and on success transition to Done status, or
// on failure to Error status.
func StatusPending() Status {
	return Status{
		Kind:      StatusKindPending,
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

// StatusError constructs the status that marks the object
// as failed to be reconciled.
func StatusError(err error) Status {
	return Status{
		Kind:      StatusKindError,
		UpdatedAt: time.Now(),
		Error:     err.Error(),
	}
}

// opResult is the outcome from reconciling a single object
type opResult struct {
	rev    statedb.Revision // revision of the object
	status Status           // the status to commit
}
