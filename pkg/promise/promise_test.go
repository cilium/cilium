// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package promise

import (
	"context"
	"errors"
	"testing"
)

func TestPromiseResolve(t *testing.T) {
	resolver, promiseI := New[int]()

	promiseU := Map(promiseI, func(n int) uint64 { return uint64(n) * 2 })

	go func() {
		resolver.Resolve(123)
		resolver.Resolve(256)
	}()

	i, err := promiseI.Await(context.TODO())
	if err != nil {
		t.Fatalf("expected nil error, got %s", err)
	}
	if i != 123 {
		t.Fatalf("expected 123, got %d", i)
	}

	u, err := promiseU.Await(context.TODO())
	if err != nil {
		t.Fatalf("expected nil error, got %s", err)
	}
	if u != 2*123 {
		t.Fatalf("expected 2*123, got %d", u)
	}
}

func TestPromiseReject(t *testing.T) {
	resolver, promise := New[int]()

	rejectError := errors.New("rejected")
	expectedError := errors.New("finalized error")

	ePromise := MapError(promise, func(err error) error {
		if errors.Is(err, rejectError) {
			return expectedError
		}
		return err
	})

	go resolver.Reject(rejectError)

	i, err := ePromise.Await(context.TODO())
	if !errors.Is(err, expectedError) {
		t.Fatalf("expected %s error, got %s", expectedError, err)
	}
	if i != 0 {
		t.Fatalf("expected zero value, got %d", i)
	}
}

func TestPromiseCancelled(t *testing.T) {
	_, promise := New[int]()

	expectedError := errors.New("finalized error")

	ePromise := MapError(promise, func(err error) error {
		if errors.Is(err, context.Canceled) {
			return expectedError
		}
		return err
	})

	ctx, cancel := context.WithCancel(context.Background())
	go cancel()
	_, err := ePromise.Await(ctx)

	if !errors.Is(err, expectedError) {
		t.Fatalf("expected %s error, got %s", expectedError, err)
	}
}
