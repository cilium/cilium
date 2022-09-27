// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"context"
	"time"

	"go.uber.org/multierr"

	"github.com/cilium/cilium/pkg/hive/internal"
)

// Hook is a pair of start and stop callbacks. Both are optional.
// They're paired up to make sure that on failed start all corresponding
// stop hooks are executed.
type Hook struct {
	OnStart func(context.Context) error
	OnStop  func(context.Context) error
}

// Lifecycle enables cells to register start and stop hooks, either
// from a constructor or an invoke function.
type Lifecycle interface {
	Append(Hook)
}

// DefaultLifecycle lifecycle implements a simple lifecycle management that conforms
// to Lifecycle. It is exported for use in applications that have nested lifecycles
// (e.g. operator).
type DefaultLifecycle struct {
	hooks      []Hook
	numStarted int
}

func (lc *DefaultLifecycle) Append(hook Hook) {
	lc.hooks = append(lc.hooks, hook)
}

func (lc *DefaultLifecycle) Start(ctx context.Context) error {
	// Wrap the context to make sure it gets cancelled after
	// start hooks have completed in order to discourage using
	// the context for unintended purposes.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, hook := range lc.hooks {
		if hook.OnStart != nil {
			fn := internal.FuncNameAndLocation(hook.OnStart)
			l := log.WithField("function", fn)
			l.Debug("Executing start hook")
			t0 := time.Now()
			if err := hook.OnStart(ctx); err != nil {
				l.WithError(err).Error("Start hook failed")
				return multierr.Combine(err, lc.Stop(ctx))
			}
			d := time.Since(t0)
			l.WithField("duration", d).Info("Start hook executed")
		}
		lc.numStarted++
	}
	return nil
}

func (lc *DefaultLifecycle) Stop(ctx context.Context) error {
	// Wrap the context to make sure it gets cancelled after
	// stop hooks have completed in order to discourage using
	// the context for unintended purposes.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var errs []error
	for ; lc.numStarted > 0; lc.numStarted-- {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		hook := lc.hooks[lc.numStarted-1]
		if hook.OnStop != nil {
			fn := internal.FuncNameAndLocation(hook.OnStop)
			l := log.WithField("function", fn)
			l.Debug("Executing stop hook")
			t0 := time.Now()
			if err := hook.OnStop(ctx); err != nil {
				l.WithError(err).Error("Stop hook failed")
				errs = append(errs, err)
			} else {
				d := time.Since(t0)
				l.WithField("duration", d).Info("Stop hook executed")
			}
		}
	}
	return multierr.Combine(errs...)
}

var _ Lifecycle = &DefaultLifecycle{}
