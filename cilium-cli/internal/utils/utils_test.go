// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package utils

import "testing"

func TestCheckVersion(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"v1.9.6", true},
		{"1.9.6", true},
		{"v1.10.0-rc1", true},
		{"1.10.0-rc1", true},
		{"1.9", false},
		{"v1.9", false},
		{"1", false},
		{"a01..0..0", false},
		{".1.9", false},
		{"..1.9", false},
		{"1...9", false},
		{"ddd", false},
		{"v.1.9", false},
		{"v..1.9", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CheckVersion(tt.name); got != tt.want {
				t.Errorf("CheckVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}
