// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package stream

import (
	"context"
	"errors"
	"io"
	"testing"
)

func TestFirst(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. First on non-empty source
	fst, err := First(ctx, Range(42, 1000))
	assertNil(t, "First", err)

	if fst != 42 {
		t.Fatalf("expected 42, got %d", fst)
	}

	// 2. First on empty source
	_, err = First(ctx, Empty[int]())
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %s", err)
	}

	// 3. cancelled context
	cancel()
	_, err = First(ctx, Stuck[int]())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected Canceled, got %s", err)
	}
}
