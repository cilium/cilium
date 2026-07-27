// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"os"
	"testing"
)

func Test_removeIfEmpty(t *testing.T) {
	t.Run("directory is empty", func(t *testing.T) {
		tempdir := t.TempDir()

		removeIfEmpty(tempdir)

		if _, err := os.Stat(tempdir); !os.IsNotExist(err) {
			t.Fatalf("%s should be removed", tempdir)
		}
	})

	t.Run("directory is not empty", func(t *testing.T) {
		tempdir := t.TempDir()

		if _, err := os.MkdirTemp(tempdir, ""); err != nil {
			t.Fatal(err)
		}

		removeIfEmpty(tempdir)

		if _, err := os.Stat(tempdir); os.IsNotExist(err) {
			t.Fatalf("%s should not be removed", tempdir)
		}
	})
}
