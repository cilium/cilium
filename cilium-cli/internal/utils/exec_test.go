// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type testLogger struct{}

func (testLogger) Log(string, ...any) {}

func TestExecInheritsEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command differs on windows")
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "print-env.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' \"$AZURE_CONFIG_DIR\"\n"), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	t.Setenv("AZURE_CONFIG_DIR", "/tmp/azure-profile")

	out, err := Exec(testLogger{}, script)
	if err != nil {
		t.Fatalf("Exec returned error: %v", err)
	}
	if string(out) != "/tmp/azure-profile" {
		t.Fatalf("unexpected output %q", string(out))
	}
}
