// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"errors"
	"os"
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
