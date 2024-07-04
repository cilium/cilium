package reconciler

import (
	"fmt"
	"time"

	"github.com/cilium/statedb"
	"golang.org/x/time/rate"
)

func defaultOptions() options {
	return options{
		Metrics: nil, // use DefaultMetrics

		// Refresh objects every 30 minutes at a rate of 100 per second.
		RefreshInterval:    30 * time.Minute,
		RefreshRateLimiter: rate.NewLimiter(100.0, 1),

		// Prune when initialized and then once an hour.
		PruneInterval: time.Hour,

		// Retry failed operations with exponential backoff from 100ms to 1min.
		RetryBackoffMinDuration: 100 * time.Millisecond,
		RetryBackoffMaxDuration: time.Minute,

		// Reconcile 100 rounds per second * 1000 yielding maximum rate of
		// 100k objects per second.
		IncrementalRoundSize: 1000,
		RateLimiter:          rate.NewLimiter(1000.0, 1),
	}
}

type options struct {
	// Metrics to use with this reconciler. The metrics capture the duration
	// of operations during incremental and full reconcilation and the errors
	// that occur during either.
	//
	// If nil, then the default metrics are used via Params.
	// A simple implementation of metrics based on the expvar package come
	// with the reconciler and a custom one can be used by implementing the
	// Metrics interface.
	Metrics Metrics

	// RefreshInterval is the interval at which the objects are refreshed,
	// e.g. how often Update() should be called to refresh an object even
	// when it has not changed. This is implemented by periodically setting
	// all objects that have not been updated for [RefreshInterval] or longer
	// as pending.
	// If set to 0 refreshing is disabled.
	RefreshInterval time.Duration

	// RefreshRateLimiter is optional and if set is used to limit the rate at
	// which objects are marked for refresh. If not provided a default rate
	// limiter is used.
	RefreshRateLimiter *rate.Limiter

	// PruneInterval is the interval at which Prune() is called to prune
	// unexpected objects in the target system. If set to 0 pruning is disabled.
	// Prune() will not be called before the table has been fully initialized
	// (Initialized() returns true).
	// A single Prune() can be forced via the [Reconciler.Prune] method regardless
	// of this value (0 or not).
	PruneInterval time.Duration

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

	// RateLimiter is optional and if set will use the limiter to wait between
	// reconciliation rounds. This allows trading latency with throughput by
	// waiting longer to collect a batch of objects to reconcile.
	RateLimiter *rate.Limiter
}

type config[Obj any] struct {
	// Table to reconcile. Mandatory.
	Table statedb.RWTable[Obj]

	// GetObjectStatus returns the reconciliation status for the object.
	// Mandatory.
	GetObjectStatus func(Obj) Status

	// SetObjectStatus sets the reconciliation status for the object.
	// This is called with a copy of the object returned by CloneObject.
	// Mandatory.
	SetObjectStatus func(Obj, Status) Obj

	// CloneObject returns a shallow copy of the object. This is used to
	// make it possible for the reconciliation operations to mutate
	// the object (to for example provide additional information that the
	// reconciliation produces) and to be able to set the reconciliation
	// status after the reconciliation.
	// Mandatory.
	CloneObject func(Obj) Obj

	// Operations defines how an object is reconciled. Mandatory.
	Operations Operations[Obj]

	// BatchOperations is optional and if provided these are used instead of
	// the single-object operations.
	BatchOperations BatchOperations[Obj]

	options
}

func (cfg config[Obj]) validate() error {
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
	if cfg.RefreshInterval < 0 {
		return fmt.Errorf("%T.RefreshInterval must be >=0", cfg)
	}
	if cfg.PruneInterval < 0 {
		return fmt.Errorf("%T.PruneInterval must be >=0", cfg)
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
