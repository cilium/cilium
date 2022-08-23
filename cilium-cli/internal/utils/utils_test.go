// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/blang/semver/v4"
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
		{"92ff7ffa762f6f8bc397a28e6f3147906e20e8fa", true},
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

func TestParseCiliumVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    semver.Version
		wantErr bool
	}{
		{
			name:    "empty",
			wantErr: true,
		},
		{
			name:    "invalid-version",
			version: "invalid",
			wantErr: true,
		},
		{
			name:    "valid-version",
			version: "v1.9.99",
			want:    semver.Version{Major: 1, Minor: 9, Patch: 99},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCiliumVersion(tt.version)
			if tt.wantErr && err == nil {
				t.Errorf("ParseCiliumVersion(%q) got nil, want error", tt.version)
			} else if !tt.wantErr && err != nil {
				t.Errorf("ParseCiliumVersion(%q) got error, want nil", tt.version)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PetCiliumVersion(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestBuildImagePath(t *testing.T) {
	tests := []struct {
		userImage      string
		userVersion    string
		defaultImage   string
		defaultVersion string
		imagePathMode  ImagePathMode
		want           string
	}{
		{
			userVersion:    "",
			defaultImage:   "quay.io/cilium/cilium",
			defaultVersion: "v1.10.4",
			imagePathMode:  ImagePathIncludeDigest,
			want:           "quay.io/cilium/cilium:v1.10.4@sha256:7d354052ccf2a7445101d78cebd14444c7c40129ce7889f2f04b89374dbf8a1d",
		},
		{
			userVersion:    "",
			defaultImage:   "quay.io/cilium/cilium",
			defaultVersion: "v1.10.4",
			want:           "quay.io/cilium/cilium:v1.10.4",
		},
		{
			userVersion:    "v1.9.10",
			defaultImage:   "quay.io/cilium/cilium",
			defaultVersion: "v1.10.4",
			want:           "quay.io/cilium/cilium:v1.9.10",
		},
		{
			userVersion:    "1.9.10",
			defaultImage:   "quay.io/cilium/cilium",
			defaultVersion: "v1.10.4",
			want:           "quay.io/cilium/cilium:v1.9.10",
		},
		{
			userVersion:    "-ci:92ff7ffa762f6f8bc397a28e6f3147906e20e8fa",
			defaultImage:   "quay.io/cilium/cilium",
			defaultVersion: "v1.10.4",
			want:           "quay.io/cilium/cilium-ci:92ff7ffa762f6f8bc397a28e6f3147906e20e8fa",
		},
		{
			userVersion:    ":latest",
			defaultImage:   "quay.io/cilium/cilium",
			defaultVersion: "v1.10.4",
			want:           "quay.io/cilium/cilium:latest",
		},
		{
			userImage:      "quay.io/cilium/cilium-ci",
			userVersion:    "v1.9.10",
			defaultImage:   "quay.io/cilium/cilium",
			defaultVersion: "v1.10.4",
			want:           "quay.io/cilium/cilium-ci:v1.9.10",
		},
		{
			userImage:      "quay.io/cilium/cilium-ci",
			userVersion:    "latest",
			defaultImage:   "quay.io/cilium/cilium",
			defaultVersion: "v1.10.4",
			want:           "quay.io/cilium/cilium-ci:latest",
		},
		{
			userImage:      "quay.io/cilium/cilium-ci:92ff7ffa762f6f8bc397a28e6f3147906e20e8fa",
			defaultImage:   "quay.io/cilium/cilium",
			defaultVersion: "v1.10.4",
			want:           "quay.io/cilium/cilium-ci:92ff7ffa762f6f8bc397a28e6f3147906e20e8fa",
		},
		{
			userVersion:    "v1.11.0",
			defaultImage:   "quay.io/cilium/cilium",
			defaultVersion: "v1.10.4",
			imagePathMode:  ImagePathIncludeDigest,
			want:           "quay.io/cilium/cilium:v1.11.0@sha256:ea677508010800214b0b5497055f38ed3bff57963fa2399bcb1c69cf9476453a",
		},
		{
			userVersion:    "v1.11.0",
			defaultImage:   "quay.io/cilium/cilium",
			defaultVersion: "v1.10.4",
			want:           "quay.io/cilium/cilium:v1.11.0",
		},
		{
			userVersion:    "-service-mesh:v1.11.0-beta.1",
			defaultImage:   "quay.io/cilium/hubble-relay",
			defaultVersion: "v1.11.0",
			imagePathMode:  ImagePathIncludeDigest,
			want:           "quay.io/cilium/hubble-relay-service-mesh:v1.11.0-beta.1@sha256:db4e82f2905073b99dc9da656a23efb6856833a8a1353f8317a3c52ff5ee53aa",
		},
	}
	for _, tt := range tests {
		ui, uv, di, dv, ipm := tt.userImage, tt.userVersion, tt.defaultImage, tt.defaultVersion, tt.imagePathMode
		fn := fmt.Sprintf("BuildImagePath(%q, %q, %q, %q, %v)", ui, uv, di, dv, ipm)
		t.Run(fn, func(t *testing.T) {
			if got := BuildImagePath(ui, uv, di, dv, ipm); got != tt.want {
				t.Errorf("%s == %q, want %q", fn, got, tt.want)
			}
		})
	}
}
