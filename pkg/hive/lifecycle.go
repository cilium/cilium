// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"context"
	"fmt"
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

func (h Hook) Start(ctx context.Context) error {
	if h.OnStart == nil {
		return nil
	}
	return h.OnStart(ctx)
}

func (h Hook) Stop(ctx context.Context) error {
	if h.OnStop == nil {
		return nil
	}
	return h.OnStop(ctx)
}

type HookInterface interface {
	// Start hook is called when the hive is started.
	// Returning a non-nil error causes the start to abort and
	// the stop hooks for already started cells to be called.
	//
	// The context is valid only for the duration of the start
	// and is used to allow aborting of start hook on timeout.
	Start(context.Context) error

	// Stop hook is called when the hive is stopped or start aborted.
	// Returning a non-nil error does not abort stopping. The error
	// is recorded and rest of the stop hooks are executed.
	Stop(context.Context) error
}

// Lifecycle enables cells to register start and stop hooks, either
// from a constructor or an invoke function.
type Lifecycle interface {
	Append(HookInterface)
}

// DefaultLifecycle lifecycle implements a simple lifecycle management that conforms
// to Lifecycle. It is exported for use in applications that have nested lifecycles
// (e.g. operator).
type DefaultLifecycle struct {
	hooks      []HookInterface
	numStarted int
}

func (lc *DefaultLifecycle) Append(hook HookInterface) {
	lc.hooks = append(lc.hooks, hook)
}

func (lc *DefaultLifecycle) Start(ctx context.Context) error {
	// Wrap the context to make sure it gets cancelled after
	// start hooks have completed in order to discourage using
	// the context for unintended purposes.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, hook := range lc.hooks {
		// Count the number of hooks processed, not the number
		// of start calls as we also support hooks with only stop
		// function.
		lc.numStarted++

		var fn string
		if hook, ok := hook.(Hook); ok {
			if hook.OnStart == nil {
				continue
			}
			fn = internal.FuncNameAndLocation(hook.OnStart)
		} else {
			fn = internal.FuncNameAndLocation(hook.Start)
		}

		l := log.WithField("function", fn)
		l.Debug("Executing start hook")
		t0 := time.Now()
		if err := hook.Start(ctx); err != nil {
			l.WithError(err).Error("Start hook failed")
			return multierr.Combine(err, lc.Stop(ctx))
		}
		d := time.Since(t0)
		l.WithField("duration", d).Info("Start hook executed")
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

		var fn string
		if hook, ok := hook.(Hook); ok {
			if hook.OnStop == nil {
				continue
			}
			fn = internal.FuncNameAndLocation(hook.OnStop)
		} else {
			fn = internal.FuncNameAndLocation(hook.Stop)
		}
		l := log.WithField("function", fn)
		l.Debug("Executing stop hook")
		t0 := time.Now()
		if err := hook.Stop(ctx); err != nil {
			l.WithError(err).Error("Stop hook failed")
			errs = append(errs, err)
		} else {
			d := time.Since(t0)
			l.WithField("duration", d).Info("Stop hook executed")
		}
	}
	return multierr.Combine(errs...)
}

func (lc *DefaultLifecycle) PrintHooks() {
	fmt.Printf("Start hooks:\n\n")
	for _, hook := range lc.hooks {
		var fn string
		if hook, ok := hook.(Hook); ok {
			if hook.OnStart == nil {
				continue
			}
			fn = internal.FuncNameAndLocation(hook.OnStart)
		} else {
			fn = internal.FuncNameAndLocation(hook.Start)
		}
		fmt.Printf("  • %s\n", fn)
	}

	fmt.Printf("\nStop hooks:\n\n")
	for i := len(lc.hooks) - 1; i >= 0; i-- {
		hook := lc.hooks[i]
		var fn string
		if hook, ok := hook.(Hook); ok {
			if hook.OnStop == nil {
				continue
			}
			fn = internal.FuncNameAndLocation(hook.OnStop)
		} else {
			fn = internal.FuncNameAndLocation(hook.Stop)
		}
		fmt.Printf("  • %s\n", fn)
	}

}

var _ Lifecycle = &DefaultLifecycle{}
