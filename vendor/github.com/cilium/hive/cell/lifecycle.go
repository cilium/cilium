// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/hive/internal"
)

// HookContext is a context passed to a lifecycle hook that is cancelled
// in case of timeout. Hooks that perform long blocking operations directly
// in the start or stop function (e.g. connecting to external services to
// initialize) must abort any such operation if this context is cancelled.
type HookContext context.Context

// HookInterface wraps the Start and Stop methods that can be appended
// to an application lifecycle.
type HookInterface interface {
	Start(HookContext) error
	Stop(HookContext) error
}

// Hook is a pair of start and stop callbacks. Both are optional.
// They're paired up to make sure that on failed start all corresponding
// stop hooks are executed.
type Hook struct {
	OnStart func(HookContext) error
	OnStop  func(HookContext) error
}

func (h Hook) Start(ctx HookContext) error {
	if h.OnStart == nil {
		return nil
	}
	return h.OnStart(ctx)
}

func (h Hook) Stop(ctx HookContext) error {
	if h.OnStop == nil {
		return nil
	}
	return h.OnStop(ctx)
}

// Lifecycle enables cells to register start and stop hooks, either
// from a constructor or an invoke function.
type Lifecycle interface {
	Append(HookInterface)

	Start(*slog.Logger, context.Context) error
	Stop(*slog.Logger, context.Context) error
	PrintHooks()
}

// DefaultLifecycle lifecycle implements a simple lifecycle management that conforms
// to Lifecycle. It is exported for use in applications that have nested lifecycles
// (e.g. operator).
type DefaultLifecycle struct {
	mu         sync.Mutex
	hooks      []augmentedHook
	numStarted int

	LogThreshold time.Duration
}

type augmentedHook struct {
	HookInterface
	moduleID FullModuleID
}

func (lc *DefaultLifecycle) Append(hook HookInterface) {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	lc.hooks = append(lc.hooks, augmentedHook{hook, nil})
}

func (lc *DefaultLifecycle) Start(log *slog.Logger, ctx context.Context) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	// Wrap the context to make sure it gets cancelled after
	// start hooks have completed in order to discourage using
	// the context for unintended purposes.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, hook := range lc.hooks {
		fnName, exists := getHookFuncName(hook, true)

		if !exists {
			// Count as started as there might be a stop hook.
			lc.numStarted++
			continue
		}

		l := log.With("function", fnName)
		l.Debug("Executing start hook")
		t0 := time.Now()
		if err := hook.Start(ctx); err != nil {
			l.Error("Start hook failed", "error", err)
			return err
		}
		d := time.Since(t0)
		if d > lc.LogThreshold {
			l.Info("Start hook executed", "duration", d)
		} else {
			l.Debug("Start hook executed", "duration", d)
		}
		lc.numStarted++
	}
	return nil
}

func (lc *DefaultLifecycle) Stop(log *slog.Logger, ctx context.Context) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	// Wrap the context to make sure it gets cancelled after
	// stop hooks have completed in order to discourage using
	// the context for unintended purposes.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var errs error
	for ; lc.numStarted > 0; lc.numStarted-- {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		hook := lc.hooks[lc.numStarted-1]

		fnName, exists := getHookFuncName(hook, false)
		if !exists {
			continue
		}
		l := log.With("function", fnName)
		l.Debug("Executing stop hook")
		t0 := time.Now()
		if err := hook.Stop(ctx); err != nil {
			l.Error("Stop hook failed", "error", err)
			errs = errors.Join(errs, err)
		} else {
			d := time.Since(t0)
			if d > lc.LogThreshold {
				l.Info("Stop hook executed", "duration", d)
			} else {
				l.Debug("Stop hook executed", "duration", d)
			}
		}
	}
	return errs
}

func (lc *DefaultLifecycle) PrintHooks() {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	fmt.Printf("Start hooks:\n\n")
	for _, hook := range lc.hooks {
		fnName, exists := getHookFuncName(hook.HookInterface, true)
		if !exists {
			continue
		}
		fmt.Printf("  • %s (%s)\n", fnName, hook.moduleID)
	}

	fmt.Printf("\nStop hooks:\n\n")
	for i := len(lc.hooks) - 1; i >= 0; i-- {
		hook := lc.hooks[i]
		fnName, exists := getHookFuncName(hook.HookInterface, false)
		if !exists {
			continue
		}
		fmt.Printf("  • %s (%s)\n", fnName, hook.moduleID)
	}
}

type augmentedLifecycle struct {
	*DefaultLifecycle
	moduleID FullModuleID
}

func (lc augmentedLifecycle) Append(hook HookInterface) {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	lc.hooks = append(lc.hooks, augmentedHook{hook, lc.moduleID})
}

func getHookFuncName(hook HookInterface, start bool) (name string, hasHook bool) {
	// Ok, we need to get a bit fancy here as runtime.FuncForPC does
	// not return what we want: we get "cell.Hook.Stop()" when we want
	// "*foo.Stop(). We do know the concrete type, and we do know
	// the method name, so we check here whether we're dealing with
	// "Hook" the struct, or an object implementing HookInterface.
	//
	// We could use reflection + FuncForPC to get around this, but it
	// still wouldn't work for generic types (file would be "<autogenerated>")
	// and the type params would be missing, so instead we'll just use the
	// type name + method name.
	switch hook := hook.(type) {
	case augmentedHook:
		name, hasHook = getHookFuncName(hook.HookInterface, start)
		if hasHook && len(hook.moduleID) > 0 {
			name = name + " (" + hook.moduleID.String() + ")"
		}
		return
	case Hook:
		if start {
			if hook.OnStart == nil {
				return "", false
			}
			return internal.FuncNameAndLocation(hook.OnStart), true
		}
		if hook.OnStop == nil {
			return "", false
		}
		return internal.FuncNameAndLocation(hook.OnStop), true

	default:
		if start {
			return internal.PrettyType(hook) + ".Start", true
		}
		return internal.PrettyType(hook) + ".Stop", true

	}
}

var _ Lifecycle = &DefaultLifecycle{}
