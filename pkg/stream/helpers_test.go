// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package stream_test

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/goleak"

	. "github.com/cilium/cilium/pkg/stream"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func assertSlice[T comparable](t *testing.T, what string, expected []T, actual []T) {
	t.Helper()
	if len(expected) != len(actual) {
		t.Fatalf("assertSlice[%s]: expected %d items, got %d (%v)", what, len(expected), len(actual), actual)
	}
	for i := range expected {
		if expected[i] != actual[i] {
			t.Fatalf("assertSlice[%s]: at index %d, expected %v, got %v", what, i, expected[i], actual[i])
		}
	}
}

func assertNil(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error in %s: %s", what, err)
	}
}

// fromCallback creates an observable that is fed by the returned 'emit' function.
// The 'stop' function is called when downstream cancels.
// Useful in tests, but unsafe in general as this creates an hot observable that only has
// sane behaviour with single observer.
func fromCallback[T any](bufSize int) (emit func(T), complete func(error), obs Observable[T]) {
	items := make(chan T, bufSize)
	errs := make(chan error, bufSize)

	emit = func(x T) {
		items <- x
	}

	complete = func(err error) {
		errs <- err
	}

	obs = FuncObservable[T](
		func(ctx context.Context, next func(T), complete func(err error)) {
			go func() {
				for {
					select {
					case <-ctx.Done():
						complete(ctx.Err())
						return
					case err := <-errs:
						complete(err)
						return
					case item := <-items:
						next(item)
					}
				}
			}()
		})

	return
}

func checkCancelled(t *testing.T, what string, src Observable[int]) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := ToSlice(ctx, src)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected Canceled error, got %s", err)
	}
	assertSlice(t, what, []int{}, result)
}
