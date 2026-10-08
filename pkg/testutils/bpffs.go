// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"os"
	"testing"
)

// TempBPFFS creates a temporary directory on a BPF FS.
//
// The directory is automatically cleaned up at the end of the test run.
func TempBPFFS(tb testing.TB) string {
	tb.Helper()

	tmp, err := os.MkdirTemp("/sys/fs/bpf", "cilium-test")
	if err != nil {
		tb.Fatal("Create temporary directory on bpffs:", err)
	}
	tb.Cleanup(func() { os.RemoveAll(tmp) })

	return tmp
}
