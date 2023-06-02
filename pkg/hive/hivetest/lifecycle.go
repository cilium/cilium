// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hivetest

import (
	"context"
	"testing"

	"github.com/cilium/cilium/pkg/hive"
)

// lifecycle implements [hive.Lifecycle] for testing purposes.
type lifecycle struct {
	tb testing.TB
}

var _ (hive.Lifecycle) = (*lifecycle)(nil)

// Lifecycle returns a [hive.Lifecycle] which executes start hooks immediately
// and queues stop hooks for the end of the test.
func Lifecycle(tb testing.TB) *lifecycle {
	return &lifecycle{tb}
}

func (lc *lifecycle) Append(hook hive.HookInterface) {
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
