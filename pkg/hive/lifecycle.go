// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"context"
	"time"

	"go.uber.org/multierr"

	"github.com/cilium/cilium/pkg/hive/internal"
)

type Hook struct {
	OnStart func(context.Context) error
	OnStop  func(context.Context) error
}

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
	for _, hook := range lc.hooks {
		if hook.OnStart != nil {
			fn := internal.FuncNameAndLocation(hook.OnStart)
			log.WithField("function", fn).Debug("Executing start hook")
			t0 := time.Now()
			if err := hook.OnStart(ctx); err != nil {
				log.WithError(err).Errorf("Failed to start %q", fn)
				return err
			}
			d := time.Since(t0)
			log.WithField("duration", d).WithField("function", fn).Info("Start hook executed")
			lc.numStarted++
		}
	}
	return nil
}

func (lc *DefaultLifecycle) Stop(ctx context.Context) error {
	var errs []error
	for ; lc.numStarted > 0; lc.numStarted-- {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		hook := lc.hooks[lc.numStarted-1]
		if hook.OnStop != nil {
			fn := internal.FuncNameAndLocation(hook.OnStart)
			log.WithField("function", fn).Debug("Executing stop hook")
			t0 := time.Now()
			if err := hook.OnStop(ctx); err != nil {
				log.WithError(err).Errorf("Failed to stop %q", fn)
				errs = append(errs, err)
			}
			d := time.Since(t0)
			log.WithField("duration", d).WithField("function", fn).Info("Stop hook executed")
		}
	}
	return multierr.Combine(errs...)
}

var _ Lifecycle = &DefaultLifecycle{}
