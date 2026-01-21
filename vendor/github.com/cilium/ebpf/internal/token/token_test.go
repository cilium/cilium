// SPDX-License-Identifier: MIT
// Copyright Cilium Contributors

package token

import (
	"sync"
	"testing"
)

func TestGetGlobalToken_DefaultValue(t *testing.T) {
	// Reset to default state
	globalTokenFD.Store(-1)

	got := GetGlobalToken()
	if got != -1 {
		t.Errorf("GetGlobalToken() = %d, want -1 (default)", got)
	}
}

func TestSetGlobalToken(t *testing.T) {
	// Reset to default state
	globalTokenFD.Store(-1)

	tests := []struct {
		name     string
		fd       int
		expected int
	}{
		{"set positive fd", 5, 5},
		{"set zero fd", 0, 0},
		{"set negative fd", -1, -1},
		{"set large fd", 1000, 1000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetGlobalToken(tt.fd)
			got := GetGlobalToken()
			if got != tt.expected {
				t.Errorf("after SetGlobalToken(%d), GetGlobalToken() = %d, want %d",
					tt.fd, got, tt.expected)
			}
		})
	}
}

func TestSetGlobalToken_Overwrite(t *testing.T) {
	// Reset to default state
	globalTokenFD.Store(-1)

	SetGlobalToken(10)
	if got := GetGlobalToken(); got != 10 {
		t.Fatalf("SetGlobalToken(10) failed, got %d", got)
	}

	SetGlobalToken(20)
	if got := GetGlobalToken(); got != 20 {
		t.Errorf("SetGlobalToken(20) did not overwrite, got %d, want 20", got)
	}
}

func TestGlobalToken_Concurrent(t *testing.T) {
	// Reset to default state
	globalTokenFD.Store(-1)

	var wg sync.WaitGroup
	iterations := 100

	// Concurrent writers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(val int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				SetGlobalToken(val)
			}
		}(i)
	}

	// Concurrent readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				got := GetGlobalToken()
				// Value should be in valid range
				if got < -1 || got > 9 {
					t.Errorf("GetGlobalToken() returned unexpected value: %d", got)
				}
			}
		}()
	}

	wg.Wait()
}
