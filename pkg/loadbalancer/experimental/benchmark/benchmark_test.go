// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package benchmark_test

import (
	"log/slog"
	"testing"

	"github.com/cilium/cilium/pkg/loadbalancer/experimental/benchmark"
)

// TestBenchmark validates that RunBenchmark() compiles and works, but only
// does one iteration and thus this is not a benchmark itself.
// run "go run ./cmd" for a proper benchmark run.
func TestBenchmark(t *testing.T) {
	benchmark.RunBenchmark(1, 1, slog.LevelError, false)
}
