// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package completion

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	TestTimeout      = 10 * time.Second
	WaitGroupTimeout = 250 * time.Millisecond
	CompletionDelay  = 250 * time.Millisecond
)

type testOwner struct {
	id      string
	cleanup func(*Completion)
}

func (o *testOwner) ID() string {
	return o.id
}

func (o *testOwner) CleanupAfterWait(c *Completion) {
	if o.cleanup != nil {
		o.cleanup(c)
	}
}

func TestCompletionBeforeWait(t *testing.T) {
	tests := []struct {
		name   string
		empty  bool
		cancel bool
		err    error
	}{
		{name: "empty", empty: true},
		{name: "canceled-empty", empty: true, cancel: true, err: context.Canceled},
		{name: "completed"},
		{name: "canceled-completed", cancel: true, err: context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			wg := NewWaitGroup(ctx)

			if !tt.empty {
				wg.AddCompletionWithCallback(nil, nil).Complete(nil)
			}
			if tt.cancel {
				cancel()
			}
			require.ErrorIs(t, wg.Wait(), tt.err)
			// Wait releases the group's context, so another wait reports cancellation.
			require.ErrorIs(t, wg.Wait(), context.Canceled)
		})
	}
}

func TestCompletionAfterWait(t *testing.T) {
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	wg := NewWaitGroup(ctx)

	comp := wg.AddCompletionWithCallback(nil, nil)

	go func() {
		time.Sleep(CompletionDelay)
		comp.Complete(nil)
	}()

	// Wait should block until comp.Complete is called, then return nil.
	err = wg.Wait()
	require.NoError(t, err)
}

func TestCompletionAfterWaitWithCancelledContext(t *testing.T) {
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	wg := NewWaitGroup(ctx)

	comp := wg.AddCompletionWithCallback(nil, nil)

	cancel()

	// Wait must settle the pending completion even though its context is canceled.
	err = wg.Wait()
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, comp.Complete(nil), context.Canceled)
}

func TestCompletionBeforeAndAfterWait(t *testing.T) {
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	wg := NewWaitGroup(ctx)

	comp1 := wg.AddCompletionWithCallback(nil, nil)

	comp2 := wg.AddCompletionWithCallback(nil, nil)

	comp1.Complete(nil)

	go func() {
		time.Sleep(CompletionDelay)
		comp2.Complete(nil)
	}()

	// Wait should block until comp2.Complete is called, then return nil.
	err = wg.Wait()
	require.NoError(t, err)
}

func TestCompletionTimeout(t *testing.T) {
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	// Set a shorter timeout to shorten the test duration.
	wgCtx, cancel := context.WithTimeout(ctx, WaitGroupTimeout)
	defer cancel()
	wg := NewWaitGroup(wgCtx)

	comp := wg.AddCompletionWithCallback(nil, func(err error) {
		// Callback gets called with context.DeadlineExceeded if the WaitGroup times out
		require.Equal(t, context.DeadlineExceeded, err)
	})

	// comp never completes.

	// Wait should block until wgCtx expires.
	err = wg.Wait()
	require.Error(t, err)

	// Errors are now different when the context times out
	require.NotEqual(t, wgCtx.Err(), err)
	require.Equal(t, context.DeadlineExceeded, wgCtx.Err())
	require.ErrorIs(t, err, context.DeadlineExceeded)

	// Complete is idempotent and harmless, and can be called after the
	// context is canceled.
	comp.Complete(nil)
}

func TestCompletionWaitCleanup(t *testing.T) {
	tests := []struct {
		name         string
		cancelGroup  bool
		cancelParent bool
		err          error
	}{
		{name: "timeout", err: context.DeadlineExceeded},
		{name: "cancel", cancelGroup: true, err: context.Canceled},
		{name: "cancel-after-parent", cancelGroup: true, cancelParent: true, err: context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), WaitGroupTimeout)
			defer cancel()
			wg := NewWaitGroup(ctx)

			var cleaned, callbacks int
			var comp *Completion
			owner := &testOwner{
				id: "cleanup-owner",
				cleanup: func(got *Completion) {
					require.Same(t, comp, got)
					cleaned++
				},
			}
			comp = wg.AddCompletionWithCallback(owner, func(err error) {
				require.ErrorIs(t, err, tt.err)
				callbacks++
			})

			if tt.cancelParent {
				cancel()
			}
			if tt.cancelGroup {
				wg.Cancel()
			} else {
				require.ErrorIs(t, wg.Wait(), tt.err)
			}
			require.Equal(t, 1, callbacks)
			require.Equal(t, 1, cleaned)
			require.ErrorIs(t, comp.Err(), tt.err)

			// Repeated cleanup and late completion must leave the settled result intact.
			wg.Cancel()
			require.ErrorIs(t, comp.Complete(nil), tt.err)
			require.Equal(t, 1, callbacks)
			require.Equal(t, 1, cleaned)
		})
	}
}

func TestCompletionWaitCleanupNotCalledOnNormalCompletion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	wg := NewWaitGroup(ctx)

	cleaned := false
	comp := wg.AddCompletionWithCallback(&testOwner{
		id: "normal-completion-owner",
		cleanup: func(*Completion) {
			cleaned = true
		},
	}, nil)

	comp.Complete(nil)

	err := wg.Wait()
	require.NoError(t, err)
	require.False(t, cleaned)
}

func TestCompletionMultipleCompleteCalls(t *testing.T) {
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	// Set a shorter timeout to shorten the test duration.
	wg := NewWaitGroup(ctx)

	comp := wg.AddCompletionWithCallback(nil, nil)

	// Complete is idempotent.
	comp.Complete(nil)
	comp.Complete(nil)
	comp.Complete(nil)

	// Wait should return immediately, since the only completion is already completed.
	err = wg.Wait()
	require.NoError(t, err)
}

func TestCompletionWithCallback(t *testing.T) {
	var err error
	var callbackCount int

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	// Set a shorter timeout to shorten the test duration.
	wg := NewWaitGroup(ctx)

	comp := wg.AddCompletionWithCallback(nil, func(err error) {
		if err == nil {
			callbackCount++
		}
	})

	// Complete is idempotent.
	comp.Complete(nil)
	comp.Complete(nil)
	comp.Complete(nil)

	// The callback is called exactly once.
	require.Equal(t, 1, callbackCount)

	// Wait should return immediately, since the only completion is already completed.
	err = wg.Wait()
	require.NoError(t, err)
}

func TestCompletionWithCallbackError(t *testing.T) {
	var err error
	var callbackCount, callbackCount2 int

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	err1 := errors.New("Error1")
	err2 := errors.New("Error2")

	// Set a shorter timeout to shorten the test duration.
	wg := NewWaitGroup(ctx)

	comp := wg.AddCompletionWithCallback(nil, func(err error) {
		callbackCount++
		// Completion that completes with a failure gets the reason for the failure
		require.Equal(t, err1, err)
	})

	wg.AddCompletionWithCallback(nil, func(err error) {
		callbackCount2++
		// When one completions fail the other completion callbacks
		// are called with context.Canceled
		require.Equal(t, context.Canceled, err)
	})

	// Complete is idempotent.
	comp.Complete(err1)
	comp.Complete(err2)
	comp.Complete(nil)

	// Wait should return immediately, since the only completion is already completed.
	err = wg.Wait()
	require.Equal(t, err1, err)

	// The callbacks are called exactly once.
	require.Equal(t, 1, callbackCount)
	require.Equal(t, 1, callbackCount2)
}

func TestCompletionWithCallbackOtherError(t *testing.T) {
	var err error
	var callbackCount, callbackCount2 int

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	err1 := errors.New("Error1")
	err2 := errors.New("Error2")

	// Set a shorter timeout to shorten the test duration.
	wg := NewWaitGroup(ctx)

	wg.AddCompletionWithCallback(nil, func(err error) {
		callbackCount++
		require.Equal(t, context.Canceled, err)
	})

	comp2 := wg.AddCompletionWithCallback(nil, func(err error) {
		callbackCount2++
		require.Equal(t, err2, err)
	})

	// Complete is idempotent.
	comp2.Complete(err2)
	comp2.Complete(err1)
	comp2.Complete(nil)

	// Wait should return immediately, since the only completion is already completed.
	err = wg.Wait()
	require.Equal(t, err2, err)

	// The callbacks are called exactly once.
	require.Equal(t, 1, callbackCount)
	require.Equal(t, 1, callbackCount2)
}

func TestCompletionWithCallbackTimeout(t *testing.T) {
	var err error
	var callbackCount int

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	// Set a shorter timeout to shorten the test duration.
	wgCtx, cancel := context.WithTimeout(ctx, WaitGroupTimeout)
	defer cancel()
	wg := NewWaitGroup(wgCtx)

	comp := wg.AddCompletionWithCallback(nil, func(err error) {
		if err == nil {
			callbackCount++
		}
		require.Equal(t, context.DeadlineExceeded, err)
	})

	// comp never completes.

	// Wait should block until wgCtx expires.
	err = wg.Wait()
	require.Error(t, err)
	// Errors are now different when the context times out
	require.NotEqual(t, wgCtx.Err(), err)
	require.Equal(t, context.DeadlineExceeded, wgCtx.Err())
	require.ErrorIs(t, err, context.DeadlineExceeded)

	// Complete is idempotent and harmless, and can be called after the
	// context is canceled.
	comp.Complete(nil)

	// The callback is only called with the error 'context.DeadlineExceeded'.
	require.Equal(t, 0, callbackCount)
}
