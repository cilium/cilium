// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package stream

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

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

func TestMap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	double := func(x int) int { return x * 2 }

	// 1. mapping a non-empty source
	{
		src := Range(0, 5)
		src = Map(src, double)
		result, err := ToSlice(ctx, src)
		assertNil(t, "case 1", err)
		assertSlice(t, "case 1", []int{0, 2, 4, 6, 8}, result)
	}

	// 2. mapping an empty source
	{
		src := Map(Empty[int](), double)
		result, err := ToSlice(ctx, src)
		assertNil(t, "case 2", err)
		assertSlice(t, "case 2", []int{}, result)
	}

	// 3. cancelled context
	checkCancelled(t, "case 3", Map(Range(0, 100), double))
}

func TestFilter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	isOdd := func(x int) bool { return x%2 != 0 }

	// 1. filtering a non-empty source
	{
		src := Range(0, 5)
		src = Filter(src, isOdd)
		result, err := ToSlice(ctx, src)
		assertNil(t, "case 1", err)
		assertSlice(t, "case 1", []int{1, 3}, result)
	}

	// 2. filtering an empty source
	{
		src := Filter(Empty[int](), isOdd)
		result, err := ToSlice(ctx, src)
		assertNil(t, "case 2", err)
		assertSlice(t, "case 2", []int{}, result)
	}

	// 3. cancelled context
	checkCancelled(t, "case 3", Filter(Range(0, 100), isOdd))
}

func TestReduce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sum := func(result, x int) int { return result + x }

	// 1. Reducing a non-empty source
	{
		src := Range(0, 5)
		src = Reduce(src, 0, sum)
		result, err := ToSlice(ctx, src)
		assertNil(t, "case 1", err)
		assertSlice(t, "case 1", []int{0 + 0 + 1 + 2 + 3 + 4}, result)
	}

	// 2. Reducing an empty source
	{
		src := Reduce(Empty[int](), 0, sum)
		result, err := ToSlice(ctx, src)
		assertNil(t, "case 2", err)
		assertSlice(t, "case 2", []int{0}, result)
	}

	// 3. cancelled context
	checkCancelled(t, "case 3", Reduce(Range(0, 100), 0, sum))
}

func TestMulticast(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	numSubs := 3

	expected := []int{1, 2, 3, 4, 5}

	in := make(chan int)

	// Create an unbuffered broadcast of 'in'
	src, connect := ToMulticast(FromChannel(in))

	subErrs := make(chan error, numSubs)
	defer close(subErrs)

	numReady := int32(0)

	for i := 0; i < numSubs; i++ {
		go func() {
			errs := make(chan error)
			items := ToChannel(ctx, errs, src)
			index := 0
			ready := false
			for {
				select {
				case item := <-items:
					if item == 0 {
						if !ready {
							atomic.AddInt32(&numReady, 1)
							ready = true
						}
					} else {
						if item != expected[index] {
							subErrs <- fmt.Errorf("%d != %d", item, expected[index])
							return
						}
						index++
					}

				case err := <-errs:
					subErrs <- err
					return
				}
			}
		}()
	}

	connect(ctx)

	// Synchronize with the subscriptions
	for atomic.LoadInt32(&numReady) != int32(numSubs) {
		in <- 0
	}

	// Feed in the actual test data.
	for _, i := range expected {
		in <- i
	}
	close(in)

	// Process errors from the subscribers
	for i := 0; i < numSubs; i++ {
		err := <-subErrs
		if err != nil {
			t.Errorf("error: %s", err)
		}
	}

	// Cancel the context and check that observing completes immediately.
	cancel()

	items, err := ToSlice(context.TODO(), src)
	if len(items) != 0 || err != nil {
		t.Fatalf("Unexpected result after cancel(): items=%v, err=%v", items, err)
	}
}

func TestMulticastCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	numSubs := 10

	src, connect := ToMulticast(Range(0, 10000))

	subErrs := make(chan error, numSubs)
	defer close(subErrs)

	for i := 0; i < numSubs; i++ {
		src.Observe(
			context.TODO(), // We don't care about cancelling the subs
			func(item int) {
				time.Sleep(time.Millisecond)
			},
			func(err error) {
				subErrs <- err
			})
	}

	connect(ctx)
	time.Sleep(10 * time.Millisecond)
	cancel()

	// Process errors from the subscribers
	for i := 0; i < numSubs; i++ {
		err := <-subErrs
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("error: %s", err)
		}
	}
}

/*
func TestMulticastEmitLatest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	expected := []int{0, 1, 2, 3, 4}
	lastItem := expected[len(expected)-1]

	src, connect := Multicast(Concat(FromSlice(expected), Stuck[int]()), )
	go connect(ctx)

	// Subscribe first to wait for all items to be emitted
	src.Observe(ctx, func(item int) error {
		if item == lastItem {
			return errors.New("stop")
		}
		return nil
	})

	// Then subscribe again to check that the latest item is seen.
	x, err := First(ctx, src)
	assertNil(t, "First", err)
	if x != lastItem {
		t.Fatalf("expected to see %d, got %d", lastItem, lastItem)
	}

}*/

func TestThrottle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	waitMillis := 20
	go func() {
		time.Sleep(time.Duration(waitMillis) * time.Millisecond)
		cancel()
	}()

	ratePerSecond := 2000.0
	values, err := ToSlice(ctx, Throttle(Range(0, 100000), ratePerSecond, 1))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected Canceled error, got %s", err)
	}

	expectedLen := int(float64(waitMillis) / 1000.0 * ratePerSecond)

	lenDiff := len(values) - expectedLen
	if lenDiff < 0 {
		lenDiff *= -1
	}
	// Check that we're within 20%
	if lenDiff > expectedLen/5 {
		t.Fatalf("expected ~%d values, got %d, diff: %d", expectedLen, len(values), lenDiff)
	}
}

func TestRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		err1 = errors.New("err1")
		err2 = errors.New("err2")
	)

	emit, complete, obs := fromCallback[int](1)
	shouldRetry := func(err error) bool {
		return errors.Is(err, err1)
	}
	// Retry if error is 'err1', otherwise stop.
	obs = Retry(obs, shouldRetry)

	errs := make(chan error)
	items := ToChannel(ctx, errs, obs)

	emit(1)
	if item := <-items; item != 1 {
		t.Fatalf("expected 1, got %d", item)
	}

	emit(2)
	if item := <-items; item != 2 {
		t.Fatalf("expected 2, got %d", item)
	}

	complete(err1) // this should be retried
	emit(3)
	if item := <-items; item != 3 {
		t.Fatalf("expected 3, got %d", item)
	}

	complete(err2) // this should stop the observing
	emit(4)        // ignored
	complete(nil)  // ignored

	if item, ok := <-items; ok {
		t.Fatalf("expected items channel to be closed, got item %d", item)
	}

	if err := <-errs; err != err2 {
		t.Fatalf("expected error %s, got %s", err2, err)
	}
}

func TestRetryFuncs(t *testing.T) {
	err := errors.New("err")

	// Retry 10 times with exponential backoff up to 10ms.
	var retry RetryFunc
	retry = AlwaysRetry
	retry = BackoffRetry(retry, time.Millisecond, 10*time.Millisecond)
	retry = LimitRetries(retry, 6)

	t0 := time.Now()
	for i := 0; i < 10; i++ {
		if i < 6 {
			if !retry(err) {
				t.Fatalf("expected retry to succeed at attempt %d", i)
			}
		} else {
			if retry(err) {
				t.Fatalf("expected retry to fail at attempt %d", i)
			}
		}
	}
	tdiff := time.Now().Sub(t0)
	expectedDiff := time.Duration(1+2+4+8+10+10) * time.Millisecond

	if tdiff < expectedDiff || tdiff > 2*expectedDiff {
		t.Fatalf("expected backoff duration to be ~%s, it was %s", expectedDiff, tdiff)
	}
}

func TestDistict(t *testing.T) {
	items := FromSlice([]int{1, 2, 3, 3, 2, 1})
	result, err := ToSlice(context.TODO(), Distinct(items))
	assertNil(t, "ToSlice+Distict", err)
	assertSlice(t, "Distinct", []int{1, 2, 3, 2, 1}, result)
}
