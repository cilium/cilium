// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
)

func TestFence(t *testing.T) {
	lc := &cell.DefaultLifecycle{}
	log := hivetest.Logger(t)

	iwg := NewFence(lc, log)

	fooStop, fooFn := testWaitFn()
	barStop, barFn := testWaitFn()

	iwg.Add("foo", fooFn)
	iwg.Add("bar", barFn)

	require.Len(t, iwg.(*fence).waitFuncs, 2)

	require.NoError(t, lc.Start(log, t.Context()))
	t.Cleanup(func() { require.NoError(t, lc.Stop(log, context.TODO())) })

	ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()
	require.ErrorIs(t, iwg.Wait(ctx), context.DeadlineExceeded)

	close(fooStop)

	ctx, cancel = context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()
	require.ErrorIs(t, iwg.Wait(ctx), context.DeadlineExceeded)

	close(barStop)

	require.NoError(t, iwg.Wait(t.Context()))
	require.NoError(t, iwg.Wait(t.Context()))

	// After we've successfully waited on everything we should forget the
	// wait functions.
	require.Empty(t, iwg.(*fence).waitFuncs)

	require.Panics(t, func() {
		iwg.Add("foo", fooFn)
	})
}

func TestFence_WaitContext(t *testing.T) {
	lc := &cell.DefaultLifecycle{}
	log := hivetest.Logger(t)

	iwg := NewFence(lc, log)
	iwg.Add("stuck", testStuckFn)
	require.NoError(t, lc.Start(log, t.Context()))
	t.Cleanup(func() { require.NoError(t, lc.Stop(log, context.TODO())) })

	ctx1, cancel1 := context.WithCancel(t.Context())
	defer cancel1()

	// Blocks until cancel1() called
	go iwg.Wait(ctx1)

	// Wait() stuck acquiring lock until context is cancelled.
	ctx2, cancel2 := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel2()
	require.ErrorIs(t, iwg.Wait(ctx2), context.DeadlineExceeded)

}

func TestFence_Errors(t *testing.T) {
	lc := &cell.DefaultLifecycle{}
	log := hivetest.Logger(t)

	iwg := NewFence(lc, log)

	var success bool
	iwg.Add("fail", testWaitFailFn(&success))

	require.Len(t, iwg.(*fence).waitFuncs, 1)

	require.NoError(t, lc.Start(log, t.Context()))
	t.Cleanup(func() { require.NoError(t, lc.Stop(log, context.TODO())) })

	require.ErrorIs(t, iwg.Wait(t.Context()), errTestWait)

	require.Len(t, iwg.(*fence).waitFuncs, 1)

	success = true

	require.NoError(t, iwg.Wait(t.Context()))
	require.NoError(t, iwg.Wait(t.Context()))

	// After we've successfully waited on everything we should forget the
	// wait functions.
	require.Empty(t, iwg.(*fence).waitFuncs)
}

func testWaitFn() (stop chan struct{}, fn WaitFunc) {
	stop = make(chan struct{})
	fn = func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-stop:
			return nil
		}
	}
	return
}

var errTestWait = errors.New("fail")

func testWaitFailFn(success *bool) WaitFunc {
	return func(ctx context.Context) error {
		if !*success {
			return errTestWait
		}
		return nil
	}
}

func testStuckFn(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}
