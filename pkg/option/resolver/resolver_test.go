// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resolver

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteConfigurations(t *testing.T) {
	dir := t.TempDir()

	out := map[string]string{
		"A": "a",
		"B": "b",
	}

	err := WriteConfigurations(context.Background(), dir, out)
	if err != nil {
		t.Fatal(err)
	}

	for k, v := range out {
		actual, err := os.ReadFile(filepath.Join(dir, k))
		if err != nil {
			t.Fatal(err)
		}
		if string(actual) != v {
			t.Fatalf("Unexpected value, wanted %s got %s", v, actual)
		}
	}
}
