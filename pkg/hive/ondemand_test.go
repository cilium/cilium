// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/hive"
)

type testResource struct {
	start int
	err   error
}

func (t *testResource) Start(*slog.Logger, context.Context) error {
	if t.err != nil {
		return t.err
	}
	t.start++
	return nil
}
func (t *testResource) Stop(*slog.Logger, context.Context) error {
	if t.err != nil {
		return t.err
	}
	t.start--
	return nil
}

func (t *testResource) Append(cell.HookInterface) {}
func (t *testResource) PrintHooks(io.Writer)      {}

var _ cell.Lifecycle = &testResource{}

func TestOnDemand(t *testing.T) {
	ctx := context.TODO()
	log := hivetest.Logger(t)

	// Test without errors
	t.Run("no-errors", func(t *testing.T) {
		r := &testResource{}
		or := hive.NewOnDemand(log, r, r)
		assert.Zero(t, r.start, "expected zero start count")

		ar1, err := or.Acquire(ctx)
		assert.NoError(t, err, "Acquire")
		assert.Same(t, r, ar1)
		assert.Equal(t, 1, r.start, "unexpected start count")

		ar2, err := or.Acquire(ctx)
		assert.NoError(t, err, "Acquire")
		assert.Same(t, r, ar2)
		assert.Equal(t, 1, r.start, "unexpected start count")

		err = or.Release(ar1)
		assert.NoError(t, err, "Release")
		assert.Equal(t, 1, r.start, "unexpected start count")

		err = or.Release(ar2)
		assert.NoError(t, err, "Release")
		assert.Equal(t, 0, r.start, "unexpected start count")
	})

	testErr := errors.New("error")

	// Test with start failure
	t.Run("start-error", func(t *testing.T) {
		r := &testResource{}
		r.err = testErr
		or := hive.NewOnDemand(log, r, r)

		ar1, err := or.Acquire(ctx)
		assert.ErrorIs(t, err, testErr)
		assert.Nil(t, ar1)
		assert.Equal(t, 0, r.start, "unexpected start count")
	})

	// Test with stop failure
	t.Run("stop-error", func(t *testing.T) {
		r := &testResource{}
		r.err = nil
		or := hive.NewOnDemand(log, r, r)

		ar1, err := or.Acquire(ctx)
		assert.NoError(t, err)
		assert.Same(t, r, ar1)
		assert.Equal(t, 1, r.start, "unexpected start count")

		r.err = testErr
		err = or.Release(ar1)
		assert.ErrorIs(t, err, testErr)
		assert.Equal(t, 1, r.start, "unexpected start count")
	})
}
