// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/lock/lockfile"
)

const lockPath = "cilium-test.lock"

// SerializedTest ensures that tests calling this helper are executed serially
// with other tests that also call this helper, specifically across different
// packages. It does not guarantee any ordering between tests in the same
// package or in others, only that tests that opted in to serialization will not
// run concurrently.
//
// `go test` executes different packages' tests in parallel by default. Some
// tests mutate system-level state, like implicitly loading a kernel module that
// spawns default tunnel interfaces in other network namespaces, or tests that
// modify sysctls. These may interfere with tests in other packages that expect
// the list of interfaces to be stable for the duration of the test.
func SerializedTest(tb testing.TB) {
	tb.Helper()

	path := filepath.Join(os.TempDir(), lockPath)

	f, err := lockfile.NewLockfile(path)
	if err != nil {
		tb.Fatalf("Failed to create lockfile: %v", err)
	}

	start := time.Now()
	if err := f.Lock(tb.Context(), true); err != nil {
		tb.Fatalf("Failed to acquire lock: %v", err)
	}
	end := time.Now()

	if blocked := end.Sub(start); blocked > 1*time.Second {
		tb.Logf("Acquired SerializedTest lock after %v", blocked)
	}

	tb.Cleanup(func() {
		if err := f.Unlock(); err != nil {
			tb.Fatalf("Failed to release lock: %v", err)
		}
		if err := f.Close(); err != nil {
			tb.Fatalf("Failed to close lockfile: %v", err)
		}
	})
}
