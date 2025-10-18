// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"time"

	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"golang.org/x/time/rate"
)

// Register creates a new reconciler and adds the reconcilation jobs to the provided
// job group.
//
// The setStatus etc. functions are passed in as arguments rather than requiring
// the object to implement them via interface as this allows constructing multiple
// reconcilers for a single object by having multiple status fields and different
// functions for manipulating them.
func Register[Obj comparable](
	// General dependencies of the reconciler.
	params Params,
	// The table to reconcile
	table statedb.RWTable[Obj],

	// Function for cloning the object.
	clone func(Obj) Obj,

	// Function for setting the status.
	setStatus func(Obj, Status) Obj,

	// Function for getting the status.
	getStatus func(Obj) Status,

	// Reconciliation operations
	ops Operations[Obj],

	// (Optional) batch operations. Set to nil if not available.
	batchOps BatchOperations[Obj],

	// zero or more options to override defaults.
	options ...Option,
) (Reconciler[Obj], error) {
	cfg := config[Obj]{
		Table:           table,
		GetObjectStatus: getStatus,
		SetObjectStatus: setStatus,
		CloneObject:     clone,
		Operations:      ops,
		BatchOperations: batchOps,
		options:         defaultOptions(),
	}
	for _, opt := range options {
		opt(&cfg.options)
	}

	if cfg.Metrics == nil {
		if params.DefaultMetrics == nil {
			cfg.Metrics = NewUnpublishedExpVarMetrics()
		} else {
			cfg.Metrics = params.DefaultMetrics
		}
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	idx := cfg.Table.PrimaryIndexer()
	objectToKey := func(o any) index.Key {
		return idx.ObjectToKey(o.(Obj))
	}
	r := &reconciler[Obj]{
		Params:               params,
		config:               cfg,
		retries:              newRetries(cfg.RetryBackoffMinDuration, cfg.RetryBackoffMaxDuration, objectToKey),
		externalPruneTrigger: make(chan struct{}, 1),
		primaryIndexer:       idx,
	}

	params.JobGroup.Add(job.OneShot("reconcile", r.reconcileLoop))
	if r.config.RefreshInterval > 0 {
		params.JobGroup.Add(job.OneShot("refresh", r.refreshLoop))
	}
	return r, nil
}

// Option for the reconciler
type Option func(opts *options)

// WithMetrics sets the [Metrics] instance to use with this reconciler.
// The metrics capture the duration of operations during incremental and
// full reconcilation and the errors that occur during either.
//
// If this option is not used, then the default metrics instance is used.
func WithMetrics(m Metrics) Option {
	return func(opts *options) {
		opts.Metrics = m
	}
}

// WithPruning enables periodic pruning (calls to Prune() operation)
// [interval] is the interval at which Prune() is called to prune
// unexpected objects in the target system.
// Prune() will not be called before the table has been fully initialized
// (Initialized() returns true).
// A single Prune() can be forced via the [Reconciler.Prune] method regardless
// if pruning has been enabled.
//
// Pruning is enabled by default. See [config.go] for the default interval.
func WithPruning(interval time.Duration) Option {
	return func(opts *options) {
		opts.PruneInterval = interval
	}
}

// WithoutPruning disabled periodic pruning.
func WithoutPruning() Option {
	return func(opts *options) {
		opts.PruneInterval = 0
	}
}

// WithRefreshing enables periodic refreshes of objects.
// [interval] is the interval at which the objects are refreshed,
// e.g. how often Update() should be called to refresh an object even
// when it has not changed. This is implemented by periodically setting
// all objects that have not been updated for [RefreshInterval] or longer
// as pending.
// [limiter] is the rate-limiter for controlling the rate at which the
// objects are marked pending.
//
// Refreshing is disabled by default.
func WithRefreshing(interval time.Duration, limiter *rate.Limiter) Option {
	return func(opts *options) {
		opts.RefreshInterval = interval
		opts.RefreshRateLimiter = limiter
	}
}

// WithRetry sets the minimum and maximum amount of time to wait before
// retrying a failed Update() or Delete() operation on an object.
// The retry wait time for an object will increase exponentially on
// subsequent failures until [maxBackoff] is reached.
func WithRetry(minBackoff, maxBackoff time.Duration) Option {
	return func(opts *options) {
		opts.RetryBackoffMinDuration = minBackoff
		opts.RetryBackoffMaxDuration = maxBackoff
	}
}

// WithRoundLimits sets the reconciliation round size and rate limit.
// [numObjects] limits how many objects are reconciled per round before
// updating their status. A high number will delay status updates and increase
// latency for those watching the object reconciliation status. A low value
// increases the overhead of the status committing and reduces effectiveness
// of the batch operations (smaller batch sizes).
// [limiter] is used to limit the number of rounds per second to allow a larger
// batch to build up and to avoid reconciliation of intermediate object states.
func WithRoundLimits(numObjects int, limiter *rate.Limiter) Option {
	return func(opts *options) {
		opts.IncrementalRoundSize = numObjects
		opts.RateLimiter = limiter
	}
}
