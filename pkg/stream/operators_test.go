// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package stream_test

import (
	"context"
	"errors"
	"testing"
	"time"

	. "github.com/cilium/cilium/pkg/stream"
)

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

func TestThrottle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	item, err := First(ctx, Throttle(Range(42, 1000), 100.0, 1))
	assertNil(t, "First", err)

	if item != 42 {
		t.Fatalf("expected 42, got %d", item)
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
	items := ToChannel(ctx, obs, WithErrorChan(errs))

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

	if item, ok := <-items; ok {
		t.Fatalf("expected items channel to be closed, got item %d", item)
	}

	if err := <-errs; !errors.Is(err, err2) {
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

func TestDebounce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	in := make(chan int, 16)

	defer close(in)
	src := FromChannel(in)
	src = Debounce(src, 5*time.Millisecond)

	errs := make(chan error)
	defer close(errs)
	out := ToChannel(ctx, src, WithErrorChan(errs))

	in <- -1
	x := <-out // first item not delayed
	if x != -1 {
		t.Fatalf("expected -1, got %d", x)
	}
	// Emit 10 batches of 3 items. We should only
	// observe the last item of each batch.
	for i := 0; i < 10*3; i += 3 {
		in <- i
		in <- i + 1
		in <- i + 2
		time.Sleep(10 * time.Millisecond)
		x := <-out
		if x != i+2 {
			t.Fatalf("expected %d, got %d", i+2, x)
		}
	}
	cancel()
	err := <-errs
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected Canceled error, got %s", err)
	}
}
