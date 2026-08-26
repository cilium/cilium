// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package benchmark_test

import (
	"log/slog"
	"testing"

	"github.com/cilium/cilium/pkg/loadbalancer/benchmark"
	"github.com/cilium/cilium/pkg/time"
)

// TestBenchmark validates that RunBenchmark() compiles and works, but only
// does one iteration and thus this is not a benchmark itself.
// run "go run ./cmd" for a proper benchmark run.
func TestBenchmark(t *testing.T) {
	// Keep this functional test from waiting for the production batching interval.
	benchmark.RunBenchmark(1, 1, 10*time.Millisecond, slog.LevelError, false)
}
