// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hivetest

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/cilium/hive/cell"
)

// lifecycle implements [cell.Lifecycle] for testing purposes.
type lifecycle struct {
	tb testing.TB
}

var _ (cell.Lifecycle) = (*lifecycle)(nil)

// Lifecycle returns a [cell.Lifecycle] which executes start hooks immediately
// and queues stop hooks for the end of the test.
func Lifecycle(tb testing.TB) *lifecycle {
	return &lifecycle{tb}
}

func (lc *lifecycle) Append(hook cell.HookInterface) {
	lc.tb.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := hook.Start(ctx); err != nil {
		lc.tb.Fatal("Execute start hook:", err)
	}

	lc.tb.Cleanup(func() {
		lc.tb.Helper()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if err := hook.Stop(ctx); err != nil && !lc.tb.Failed() {
			lc.tb.Fatal("Execute stop hook:", err)
		}
	})
}

// PrintHooks implements cell.Lifecycle.
func (*lifecycle) PrintHooks(io.Writer) {
	panic("unimplemented")
}

// Start implements cell.Lifecycle.
func (*lifecycle) Start(*slog.Logger, context.Context) error {
	panic("unimplemented")
}

// Stop implements cell.Lifecycle.
func (*lifecycle) Stop(*slog.Logger, context.Context) error {
	panic("unimplemented")
}
