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

func TestNoCompletion(t *testing.T) {
	var err error

	wg, cancel := NewWaitGroup(context.Background(), TestTimeout)
	defer cancel()

	// Ensure context is not cancelled
	require.NoError(t, wg.Context().Err())

	// Wait should return immediately, since there are no completions.
	err = wg.Wait()
	require.NoError(t, err)
}

func TestCompletionReuseAfterWait(t *testing.T) {
	var err error

	wg, cancel := NewWaitGroup(context.Background(), TestTimeout)
	defer cancel()

	comp := wg.AddCompletion()

	comp.Complete(nil)

	// Wait should return immediately, since the only completion is already completed.
	err = wg.Wait()
	require.NoError(t, err)

	// add a new completion after the first Wait and make sure 2nd Wait actually waits for the
	// completion before returning.
	comp2 := wg.AddCompletion()

	var completionTime time.Time
	go func() {
		time.Sleep(CompletionDelay)
		completionTime = time.Now()
		comp2.Complete(nil)
	}()

	// Wait should wait for comp2 to be completed.
	err = wg.Wait()
	require.NoError(t, err)

	require.GreaterOrEqual(t, time.Now(), completionTime)
}

func TestCompletionBeforeWait(t *testing.T) {
	var err error

	wg, cancel := NewWaitGroup(context.Background(), TestTimeout)
	defer cancel()

	comp := wg.AddCompletion()

	comp.Complete(nil)

	// Wait should return immediately, since the only completion is already completed.
	err = wg.Wait()
	require.NoError(t, err)
}

func TestCompletionAfterWait(t *testing.T) {
	var err error

	wg, cancel := NewWaitGroup(context.Background(), TestTimeout)
	defer cancel()

	comp := wg.AddCompletion()

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

	wg, cancel := NewWaitGroup(context.Background(), TestTimeout)
	defer cancel()

	comp := wg.AddCompletion()

	cancel()

	go func() {
		time.Sleep(CompletionDelay)
		comp.Complete(nil)
	}()

	// Wait should block until comp.Complete is called, an error as the context was cancelled
	err = wg.Wait()
	require.ErrorIs(t, err, context.Canceled)
}

func TestCompletionBeforeAndAfterWait(t *testing.T) {
	var err error

	wg, cancel := NewWaitGroup(context.Background(), TestTimeout)
	defer cancel()

	comp1 := wg.AddCompletion()

	comp2 := wg.AddCompletion()

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
	wg, cancel := NewWaitGroup(ctx, WaitGroupTimeout)
	defer cancel()

	comp := wg.AddCompletionWithCallback(func(err error) {
		// Callback gets called with context.DeadlineExceeded if the WaitGroup times out
		require.Equal(t, context.DeadlineExceeded, err)
	})

	// comp never completes.

	// Wait should block until wg expires.
	err = wg.Wait()
	require.Error(t, err)
	require.Equal(t, wg.Context().Err(), err)

	// Complete is idempotent and harmless, and can be called after the
	// context is canceled.
	comp.Complete(nil)
}

func TestCompletionMultipleCompleteCalls(t *testing.T) {
	var err error

	wg, cancel := NewWaitGroup(context.Background(), TestTimeout)
	defer cancel()

	comp := wg.AddCompletion()

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

	wg, cancel := NewWaitGroup(context.Background(), TestTimeout)
	defer cancel()

	comp := wg.AddCompletionWithCallback(func(err error) {
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

	wg, cancel := NewWaitGroup(context.Background(), TestTimeout)
	defer cancel()

	err1 := errors.New("Error1")
	err2 := errors.New("Error2")

	comp := wg.AddCompletionWithCallback(func(err error) {
		callbackCount++
		// Completion that completes with a failure gets the reason for the failure
		require.Equal(t, err1, err)
	})

	wg.AddCompletionWithCallback(func(err error) {
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

	wg, cancel := NewWaitGroup(context.Background(), TestTimeout)
	defer cancel()

	err1 := errors.New("Error1")
	err2 := errors.New("Error2")

	wg.AddCompletionWithCallback(func(err error) {
		callbackCount++
		require.Equal(t, context.Canceled, err)
	})

	comp2 := wg.AddCompletionWithCallback(func(err error) {
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
	wg, cancel := NewWaitGroup(ctx, WaitGroupTimeout)
	defer cancel()

	comp := wg.AddCompletionWithCallback(func(err error) {
		if err == nil {
			callbackCount++
		}
		require.Equal(t, context.DeadlineExceeded, err)
	})

	// comp never completes.

	// Wait should block until wgCtx expires.
	err = wg.Wait()
	require.Error(t, err)
	require.Equal(t, wg.Context().Err(), err)

	// Complete is idempotent and harmless, and can be called after the
	// context is canceled.
	comp.Complete(nil)

	// The callback is only called with the error 'context.DeadlineExceeded'.
	require.Equal(t, 0, callbackCount)
}
