// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package utils

import (
	"fmt"
	"testing"
)

func TestCheckVersion(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"0.0.1", true},
		{"v0.0.1", true},
		{"v1.9.6", true},
		{"v1.9.6.5", false},
		{"1.9.6", true},
		{"1.9.6.5", false},
		{"v1.10.0-rc1", true},
		{"1.10.0-rc1", true},
		{"10.42.0", true},
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
		{":latest", true},
		{":92ff7ffa762f6f8bc397a28e6f3147906e20e8fa", true},
		{":92ff7ffa762f6f8bc397a28e6f3147906e20e8fa@sha256:4fde4abc19a1cbedb5084f683f5d91c0ea04b964a029e6d0ba43961e1ff5b5d8", true},
		{"-ci:92ff7ffa762f6f8bc397a28e6f3147906e20e8fa", true},
		{"-ci:92ff7ffa762f6f8bc397a28e6f3147906e20e8fa@sha256:4fde4abc19a1cbedb5084f683f5d91c0ea04b964a029e6d0ba43961e1ff5b5d8", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CheckVersion(tt.name); got != tt.want {
				t.Errorf("CheckVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildImagePath(t *testing.T) {
	defaultImage := "quay.io/cilium/cilium:v1.10.4@sha256:7d354052ccf2a7445101d78cebd14444c7c40129ce7889f2f04b89374dbf8a1d"
	tests := []struct {
		userImage     string
		userVersion   string
		imagePathMode ImagePathMode
		want          string
	}{
		{
			userVersion:   "",
			imagePathMode: ImagePathIncludeDigest,
			want:          "quay.io/cilium/cilium:v1.10.4@sha256:7d354052ccf2a7445101d78cebd14444c7c40129ce7889f2f04b89374dbf8a1d",
		},
		{
			userVersion: "",
			want:        "quay.io/cilium/cilium:v1.10.4",
		},
		{
			userVersion: "v1.9.10",
			want:        "quay.io/cilium/cilium:v1.9.10",
		},
		{
			userVersion: "1.9.10",
			want:        "quay.io/cilium/cilium:v1.9.10",
		},
		{
			userVersion: "-ci:92ff7ffa762f6f8bc397a28e6f3147906e20e8fa",
			want:        "quay.io/cilium/cilium-ci:92ff7ffa762f6f8bc397a28e6f3147906e20e8fa",
		},
		{
			userVersion: ":latest",
			want:        "quay.io/cilium/cilium:latest",
		},
		{
			userImage:   "quay.io/cilium/cilium-ci",
			userVersion: "v1.9.10",
			want:        "quay.io/cilium/cilium-ci:v1.9.10",
		},
		{
			userImage:   "quay.io/cilium/cilium-ci",
			userVersion: "latest",
			want:        "quay.io/cilium/cilium-ci:latest",
		},
		{
			userImage: "quay.io/cilium/cilium-ci:92ff7ffa762f6f8bc397a28e6f3147906e20e8fa",
			want:      "quay.io/cilium/cilium-ci:92ff7ffa762f6f8bc397a28e6f3147906e20e8fa",
		},
		{
			userVersion:   "v1.11.0",
			imagePathMode: ImagePathIncludeDigest,
			want:          "quay.io/cilium/cilium:v1.11.0@sha256:ea677508010800214b0b5497055f38ed3bff57963fa2399bcb1c69cf9476453a",
		},
		{
			userVersion: "v1.11.0",
			want:        "quay.io/cilium/cilium:v1.11.0",
		},
	}
	for _, tt := range tests {
		ui, uv, di, ipm := tt.userImage, tt.userVersion, defaultImage, tt.imagePathMode
		fn := fmt.Sprintf("BuildImagePath(%q, %q, %q, %v)", ui, uv, di, ipm)
		t.Run(fn, func(t *testing.T) {
			if got := BuildImagePath(ui, uv, di, ipm); got != tt.want {
				t.Errorf("%s == %q, want %q", fn, got, tt.want)
			}
		})
	}
}
