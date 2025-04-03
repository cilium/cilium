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

func FindInPath(t testing.TB, file string) string {
	t.Helper()

	// This logic adapted from os/exec.LookPath except for the parts that
	// check if the file is executable.
	path := os.Getenv("PATH")
	for _, dir := range filepath.SplitList(path) {
		if dir == "" {
			// Unix shell semantics: path element "" means "."
			dir = "."
		}
		path := filepath.Join(dir, file)
		d, err := os.Stat(path)
		if err != nil {
			continue
		}
		m := d.Mode()
		if m.IsDir() {
			continue
		}

		return path
	}

	t.Fatalf("%s not found", file)

	return ""
}
