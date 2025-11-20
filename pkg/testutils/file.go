// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func SkipIfFileMissing(t testing.TB, file string) {
	_, err := os.Open(file)
	if errors.Is(err, os.ErrNotExist) {
		t.Skipf("Skipping due to missing file %s", file)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// Glob returns the list of files matching pattern or fails the test if an error
// occurs.
func Glob(tb testing.TB, pattern string) []string {
	tb.Helper()

	files, err := filepath.Glob(pattern)
	if err != nil {
		tb.Fatal("Can't glob files:", err)
	}

	return files
}

// BenchmarkFiles runs sub-benchmarks for each file in files, calling fn with
// the testing.B and the file path.
func BenchmarkFiles(b *testing.B, files []string, fn func(*testing.B, string)) {
	b.Helper()

	if len(files) == 0 {
		b.Skip("No files given")
	}

	for _, f := range files {
		b.Run(filepath.Base(f), func(b *testing.B) {
			fn(b, f)
		})
	}
}
