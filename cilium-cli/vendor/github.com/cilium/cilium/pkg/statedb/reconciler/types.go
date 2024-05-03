// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/time"
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

	// WithObjectStatus returns a COPY of the object with the status set to
	// the given value.
	WithObjectStatus func(Obj, Status) Obj

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
	if cfg.GetObjectStatus == nil {
		return fmt.Errorf("%T.GetObjectStatus cannot be nil", cfg)
	}
	if cfg.WithObjectStatus == nil {
		return fmt.Errorf("%T.WithObjectStatus cannot be nil", cfg)
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
// and a ReadTxn to allow for the option of looking up realized state from another
// statedb table as an optimization (main use-case is reconciling routes against
// Table[Route] to avoid a syscall per route).
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
	// If 'changed' is non-nil then the Update must compare the realized state
	// with the desired state and set it to true if they differ, e.g. whether
	// the operation resulted in a change to the realized state. This is used
	// during full reconciliation to catch cases where the realized state has
	// gone out of sync due to outside influence. This is tracked in the
	// "full_out_of_sync_total" metric.
	Update(ctx context.Context, txn statedb.ReadTxn, obj Obj, changed *bool) error

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
	StatusKindPending StatusKind = "pending"
	StatusKindDone    StatusKind = "done"
	StatusKindError   StatusKind = "error"
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
// the reconciler.
type Status struct {
	Kind StatusKind

	// Delete is true if the object should be deleted by the reconciler.
	// If an object is deleted outside the reconciler it will not be
	// processed by the incremental reconciliation.
	// We use soft deletes in order to observe and wait for deletions.
	Delete bool

	UpdatedAt time.Time
	Error     string
}

func (s Status) String() string {
	if s.Kind == StatusKindError {
		return fmt.Sprintf("%s (delete: %v, updated: %s ago, error: %s)", s.Kind, s.Delete, time.Now().Sub(s.UpdatedAt), s.Error)
	}
	return fmt.Sprintf("%s (delete: %v, updated: %s ago)", s.Kind, s.Delete, time.Now().Sub(s.UpdatedAt))
}

// StatusPending constructs the status for marking the object as
// requiring reconciliation. The reconciler will perform the
// Update operation and on success transition to Done status, or
// on failure to Error status.
func StatusPending() Status {
	return Status{
		Kind:      StatusKindPending,
		UpdatedAt: time.Now(),
		Delete:    false,
		Error:     "",
	}
}

// StatusPendingDelete constructs the status for marking the
// object to be deleted.
//
// The reconciler uses soft-deletes in order to be able to
// retry and to report failed deletions of objects.
// When the delete operation is successfully performed
// the reconciler will delete the object from the table.
func StatusPendingDelete() Status {
	return Status{
		Kind:      StatusKindPending,
		UpdatedAt: time.Now(),
		Delete:    true,
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
func StatusError(delete bool, err error) Status {
	return Status{
		Kind:      StatusKindError,
		UpdatedAt: time.Now(),
		Delete:    delete,
		Error:     err.Error(),
	}
}

// opResult is the outcome from reconciling a single object
type opResult struct {
	rev    statedb.Revision // revision of the object
	status Status           // the status to commit
	delete bool             // if true delete object from the table
}
