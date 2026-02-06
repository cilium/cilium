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

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	wg, cancel := NewWaitGroup(ctx)
	defer cancel()

	// Wait should return immediately, since there are no completions.
	err = wg.Wait()
	require.NoError(t, err)

	// A consecutive wait should also return nil
	err = wg.Wait()
	require.NoError(t, err)
}

func TestCompletionBeforeWait(t *testing.T) {
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	wg, cancel := NewWaitGroup(ctx)
	defer cancel()

	comp := wg.AddCompletion()

	comp.Complete(nil)

	// Wait should return immediately, since the only completion is already completed.
	err = wg.Wait()
	require.NoError(t, err)
}

func TestCompletionAfterWait(t *testing.T) {
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	wg, cancel := NewWaitGroup(ctx)
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

func TestCompletionBeforeAndAfterWait(t *testing.T) {
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	wg, cancel := NewWaitGroup(ctx)
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
	wgCtx, cancel := context.WithTimeout(ctx, WaitGroupTimeout)
	defer cancel()
	wg, cancel := NewWaitGroup(wgCtx)
	defer cancel()

	comp := wg.AddCompletionWithCallback(func(err error) {
		// Callback gets called with context.DeadlineExceeded if the WaitGroup times out
		require.Equal(t, context.DeadlineExceeded, err)
	})

	// comp never completes.

	// Wait should block until wgCtx expires.
	err = wg.Wait()
	require.Error(t, err)
	require.Equal(t, wgCtx.Err(), err)

	// Complete is idempotent and harmless, and can be called after the
	// context is canceled.
	comp.Complete(nil)
}

func TestCompletionMultipleCompleteCalls(t *testing.T) {
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	// Set a shorter timeout to shorten the test duration.
	wg, cancel := NewWaitGroup(ctx)
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

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	// Set a shorter timeout to shorten the test duration.
	wg, cancel := NewWaitGroup(ctx)
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

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	err1 := errors.New("Error1")
	err2 := errors.New("Error2")

	// Set a shorter timeout to shorten the test duration.
	wg, cancel := NewWaitGroup(ctx)
	defer cancel()

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

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	err1 := errors.New("Error1")
	err2 := errors.New("Error2")

	// Set a shorter timeout to shorten the test duration.
	wg, cancel := NewWaitGroup(ctx)

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

	// Cancel wg
	cancel()
	err = wg.Wait()
	require.NoError(t, err)

	// Add and complete a complete it, and ensure Wait still returns true
	err = wg.AddCompletionWithCallback(func(err error) {}).Complete(nil)
	require.NoError(t, err)
	err = wg.Wait()
	require.NoError(t, err)

	// Add a complete that is running even tough waitGroup is closed and check that wait returns an error
	_ = wg.AddCompletionWithCallback(func(err error) {})
	require.NoError(t, err)
	err = wg.Wait()
	require.Equal(t, wg.Context().Err(), err)

}

func TestCompletionWithCallbackTimeout(t *testing.T) {
	var err error
	var callbackCount int

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	// Set a shorter timeout to shorten the test duration.
	wgCtx, cancel := context.WithTimeout(ctx, WaitGroupTimeout)
	defer cancel()

	wg, cancel := NewWaitGroup(wgCtx)
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
	require.Equal(t, wgCtx.Err(), err)

	// Consecutive waits should always return nil as long as no other
	err = wg.Wait()
	require.NoError(t, err)

	// Complete is idempotent and harmless, and can be called after the
	// context is canceled.
	comp.Complete(nil)

	// The callback is only called with the error 'context.DeadlineExceeded'.
	require.Equal(t, 0, callbackCount)
}
