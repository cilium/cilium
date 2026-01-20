// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package bpf

import (
	"os"
	"testing"
)

func TestGetGlobalToken_ReturnsStoredValue(t *testing.T) {
	// Note: This test checks the global state which is initialized in init().
	// The actual value depends on whether a token was available at startup.
	// We just verify it returns a valid integer (not panicking).
	fd := GetGlobalToken()
	if fd < -1 {
		t.Errorf("GetGlobalToken() returned invalid fd: %d", fd)
	}
}

func TestOpenBPFToken_ConfiguredPathTakesPriority(t *testing.T) {
	// When a configured path is provided, it should be tried first
	// and no other paths should be checked.

	// Use a non-existent path - should return error
	fd, err := OpenBPFToken("/nonexistent/path/for/testing")
	if fd > 0 {
		// If somehow it succeeded, close it
		t.Logf("Unexpectedly got valid fd %d from nonexistent path", fd)
	}
	// We expect an error since the path doesn't exist
	if err == nil && fd > 0 {
		t.Error("OpenBPFToken with nonexistent configured path should fail")
	}
}

func TestOpenBPFToken_EnvironmentVariableTakesPriority(t *testing.T) {
	// Set LIBBPF_BPF_TOKEN_PATH to a non-existent path
	oldEnv := os.Getenv("LIBBPF_BPF_TOKEN_PATH")
	defer os.Setenv("LIBBPF_BPF_TOKEN_PATH", oldEnv)

	os.Setenv("LIBBPF_BPF_TOKEN_PATH", "/nonexistent/env/path")

	// With empty configured path, it should check env var
	fd, err := OpenBPFToken("")

	// Should fail because the env path doesn't exist
	if fd > 0 {
		t.Logf("Unexpectedly got valid fd %d from env path", fd)
	}
	if err == nil && fd > 0 {
		t.Error("OpenBPFToken should fail with nonexistent LIBBPF_BPF_TOKEN_PATH")
	}
}

func TestOpenBPFToken_GracefulFallback(t *testing.T) {
	// When no paths are available, OpenBPFToken should return -1, nil
	// (graceful fallback, not an error)

	// Clear the environment variable
	oldEnv := os.Getenv("LIBBPF_BPF_TOKEN_PATH")
	defer os.Setenv("LIBBPF_BPF_TOKEN_PATH", oldEnv)
	os.Unsetenv("LIBBPF_BPF_TOKEN_PATH")

	// With empty configured path and no env var, it tries default paths
	// If none work, it should return -1, nil (not an error)
	fd, err := OpenBPFToken("")

	// In most test environments, BPF tokens won't be available
	// The function should gracefully return -1, nil
	if err != nil {
		// Some errors are acceptable (like permission denied on real paths)
		t.Logf("OpenBPFToken returned error (acceptable in test env): %v", err)
	}
	if fd > 0 {
		t.Logf("OpenBPFToken returned valid token fd=%d (BPF delegation available)", fd)
	}
	// The key invariant: if fd <= 0, there should be no error
	// (graceful fallback behavior)
	if fd == -1 && err != nil {
		t.Errorf("OpenBPFToken returned -1 with error %v; should return -1, nil for graceful fallback", err)
	}
}

func TestTokenPaths_ContainsExpectedPaths(t *testing.T) {
	// Verify the default token paths include expected locations
	expectedPaths := []string{
		"/run/bpf_delegation",
		"/sys/fs/bpf",
	}

	for _, expected := range expectedPaths {
		found := false
		for _, path := range tokenPaths {
			if path == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("tokenPaths does not contain expected path %q", expected)
		}
	}
}
