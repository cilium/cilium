// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"context"
	"fmt"
	"reflect"
	"runtime"

	"go.uber.org/fx"
	"go.uber.org/multierr"
)

type Hook = fx.Hook
type Lifecycle = fx.Lifecycle

// SimpleLifecycle implements a simple lifecycle management that conforms
// to 'fx.Lifecycle'. For use with 'cell.WithCustomLifecycle' for
// creating applications with nested lifecycles.
type SimpleLifecycle struct {
	hooks      []fx.Hook
	numStarted int
}

func (lc *SimpleLifecycle) Append(hook Hook) {
	lc.hooks = append(lc.hooks, hook)
}

func (lc *SimpleLifecycle) Start(ctx context.Context) error {
	for _, hook := range lc.hooks {
		if hook.OnStart != nil {
			fn := funcName(hook.OnStart)
			log.Debugf("Starting %q", fn)
			if err := hook.OnStart(ctx); err != nil {
				log.WithError(err).Errorf("Failed to start %q", fn)
				return err
			}
			lc.numStarted++
		}
	}
	return nil
}

func (lc *SimpleLifecycle) Stop(ctx context.Context) error {
	var errs []error
	for ; lc.numStarted > 0; lc.numStarted-- {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		hook := lc.hooks[lc.numStarted-1]
		if hook.OnStop != nil {
			fn := funcName(hook.OnStart)
			log.Debugf("Stopping %q", fn)
			if err := hook.OnStop(ctx); err != nil {
				log.WithError(err).Errorf("Failed to stop %q", fn)
				errs = append(errs, err)
			}
		}
	}
	return multierr.Combine(errs...)
}

func funcName(fn any) string {
	v := reflect.ValueOf(fn)
	if v.Kind() != reflect.Func {
		return fmt.Sprint(fn)
	}
	return fmt.Sprintf("%s()", runtime.FuncForPC(v.Pointer()).Name())
}

var _ Lifecycle = &SimpleLifecycle{}
