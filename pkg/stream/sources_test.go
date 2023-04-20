// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package stream_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/cilium/cilium/pkg/stream"
)

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
			items := ToChannel(ctx, src, WithErrorChan(errs))
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

	// Cancel the context and check that observing now completes immediately.
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
