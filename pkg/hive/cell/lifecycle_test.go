// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/hive/cell"
)

var (
	started, stopped int

	errLifecycle = errors.New("nope")

	goodHook = cell.Hook{
		OnStart: func(cell.HookContext) error {
			started++
			return nil
		},
		OnStop: func(cell.HookContext) error {
			stopped++
			return nil
		},
	}

	badStartHook = cell.Hook{
		OnStart: func(cell.HookContext) error {
			return errLifecycle
		},
	}

	badStopHook = cell.Hook{
		OnStart: func(cell.HookContext) error {
			started++
			return nil
		},
		OnStop: func(cell.HookContext) error {
			return errLifecycle
		},
	}

	nilHook = cell.Hook{nil, nil}
)

func TestLifecycle(t *testing.T) {
	var lc cell.DefaultLifecycle

	// Test without any hooks
	lc = cell.DefaultLifecycle{}
	err := lc.Start(context.TODO())
	assert.NoError(t, err, "expected Start to succeed")
	err = lc.Stop(context.TODO())
	assert.NoError(t, err, "expected Stop to succeed")

	// Test with 3 good, 1 nil hook, all successful.
	lc = cell.DefaultLifecycle{}
	lc.Append(goodHook)
	lc.Append(goodHook)
	lc.Append(goodHook)
	lc.Append(nilHook)

	err = lc.Start(context.TODO())
	assert.NoError(t, err, "expected Start to succeed")
	err = lc.Stop(context.TODO())
	assert.NoError(t, err, "expected Stop to succeed")

	assert.Equal(t, 3, started)
	assert.Equal(t, 3, stopped)
	started = 0
	stopped = 0

	// Test with 2 good, 1 bad start. Should see
	// the good ones stopped.
	lc = cell.DefaultLifecycle{}
	lc.Append(goodHook)
	lc.Append(goodHook)
	lc.Append(badStartHook)

	err = lc.Start(context.TODO())
	assert.ErrorIs(t, err, errLifecycle, "expected Start to fail")

	assert.Equal(t, 2, started)
	started = 0
	stopped = 0

	// Test with 2 good, 1 bad stop. Stop should return the error.
	lc = cell.DefaultLifecycle{}
	lc.Append(goodHook)
	lc.Append(goodHook)
	lc.Append(badStopHook)

	err = lc.Start(context.TODO())
	assert.NoError(t, err, "expected Start to succeed")
	assert.Equal(t, 3, started)
	assert.Equal(t, 0, stopped)

	err = lc.Stop(context.TODO())
	assert.ErrorIs(t, err, errLifecycle, "expected Stop to fail")
	assert.Equal(t, 2, stopped)
	started = 0
	stopped = 0

	// Test that one can have hook with a stop and no start.
	lc = cell.DefaultLifecycle{}
	lc.Append(cell.Hook{
		OnStop: func(cell.HookContext) error { stopped++; return nil },
	})
	err = lc.Start(context.TODO())
	assert.NoError(t, err, "expected Start to succeed")
	err = lc.Stop(context.TODO())
	assert.NoError(t, err, "expected Stop to succeed")
	assert.Equal(t, 1, stopped)

	started = 0
	stopped = 0
}

func TestLifecycleCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Test cancellation in start hook
	lc := cell.DefaultLifecycle{}
	lc.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			<-ctx.Done()
			return ctx.Err()
		},
	})
	err := lc.Start(ctx)
	assert.ErrorIs(t, err, context.Canceled)

	// Test cancellation in stop hook
	expectedErr := errors.New("stop cancelled")
	ctx, cancel = context.WithCancel(context.Background())
	inStop := make(chan struct{})
	lc = cell.DefaultLifecycle{}
	lc.Append(cell.Hook{
		OnStop: func(ctx cell.HookContext) error {
			close(inStop)
			<-ctx.Done()
			assert.ErrorIs(t, ctx.Err(), context.Canceled)
			return expectedErr
		},
	})

	// Only cancel once we're inside stop as cell.Stop() short-circuits
	// when context is cancelled.
	go func() {
		<-inStop
		cancel()
	}()

	err = lc.Start(ctx)
	assert.NoError(t, err)

	err = lc.Stop(ctx)
	assert.ErrorIs(t, err, expectedErr)
}
