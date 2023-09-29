package reconciler

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/statedb"
)

type Config struct {
	FullReconcilationInterval time.Duration
	RetryBackoffMinDuration   time.Duration
	RetryBackoffMaxDuration   time.Duration
}

var DefaultConfig = Config{
	FullReconcilationInterval: 5 * time.Minute,
	RetryBackoffMinDuration:   50 * time.Millisecond,
	RetryBackoffMaxDuration:   time.Minute,
}

type Reconciler[Obj Reconcilable[Obj]] interface {
	TriggerSync()
}

// Reconcilable objects are Go types that carry a reconciliation status.
// The generic reconciler uses WithStatus() to update the status of each
// reconciled object. This status can then be used to implement waiting.
type Reconcilable[Obj comparable] interface {
	comparable

	GetStatus() Status

	// WithStatus returns a clone of the object with the specified
	// status.
	WithStatus(Status) Obj
}

// Target captures the effectful operations for reconciling
// an object.
type Target[Obj Reconcilable[Obj]] interface {
	// Init initializes the reconciliation target. This is invoked before any
	// reconciliation operations and will be retried until it succeeds.
	Init(context.Context) error

	// Update the object in the target. If the operation is long-running it should
	// abort if context is cancelled. Should return an error if the operation fails.
	// The reconciler will retry the operation again at a later time, potentially
	// with a new version of the object. The operation should thus be idempotent.
	Update(context.Context, statedb.ReadTxn, Obj) error

	// TODO: UpdateBatch(...) for BPF map batch operations?

	// Delete the object in the target. Same semantics as with Update.
	Delete(context.Context, statedb.ReadTxn, Obj) error

	// Sync performs full reconciliation.
	// As full reconciliation is performed after incremental reconciliation,
	// we do not expect this to actually do anything. If there is something
	// to be reconciled the 'outOfSync' is returned as true. If these
	// operations failed, then 'err' is also non-nil and this will be retried
	// (after backoff).
	Sync(context.Context, statedb.ReadTxn, statedb.Iterator[Obj]) (outOfSync bool, err error)
}

type StatusKind string

const (
	StatusKindPending StatusKind = "pending"
	StatusKindDone    StatusKind = "done"
	StatusKindError   StatusKind = "error"
)

// Status is embedded into the reconcilable object. It allows
// inspecting per-object reconcilation status and waiting for
// the reconciler.
type Status struct {
	Kind StatusKind

	// Delete is true if the object should be deleted by the reconciler.
	// If an object is deleted outside the reconciler it will not be
	// processed by the incremental reconciliation.
	// We use soft deletes in order to observe and wait for deletions.
	Delete bool

	UpdatedAt time.Time
	Error     error
}

func (s Status) String() string {
	if s.Kind == StatusKindError {
		return fmt.Sprintf("%s (delete: %v, updated: %s ago, error: %s)", s.Kind, s.Delete, time.Now().Sub(s.UpdatedAt), s.Error)
	}
	return fmt.Sprintf("%s (delete: %v, updated: %s ago)", s.Kind, s.Delete, time.Now().Sub(s.UpdatedAt))
}

func StatusPending() Status {
	return Status{
		Kind:      StatusKindPending,
		UpdatedAt: time.Now(),
		Delete:    false,
		Error:     nil,
	}
}

func StatusPendingDelete() Status {
	return Status{
		Kind:      StatusKindPending,
		UpdatedAt: time.Now(),
		Delete:    true,
		Error:     nil,
	}
}

func StatusDone() Status {
	return Status{
		Kind:      StatusKindDone,
		UpdatedAt: time.Now(),
		Error:     nil,
	}
}

func StatusError(delete bool, err error) Status {
	return Status{
		Kind:      StatusKindError,
		UpdatedAt: time.Now(),
		Delete:    delete,
		Error:     err,
	}
}
