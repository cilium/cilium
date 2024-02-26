// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"os"
	"reflect"
	"testing"

	"github.com/blang/semver/v4"
	"github.com/stretchr/testify/assert"
)

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
		{
			name:    "valid-pre-release-version",
			version: "1.13.90-dev.1234-main-5678abcd",
			want: semver.Version{
				Major: 1,
				Minor: 13,
				Patch: 90,
				Pre: []semver.PRVersion{
					{VersionStr: "dev", IsNum: false},
					{VersionStr: "1234-main-5678abcd", IsNum: false},
				},
			},
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

func TestIsInHelmMode(t *testing.T) {
	orig := os.Getenv(CLIModeVariableName)
	defer func() {
		assert.NoError(t, os.Setenv(CLIModeVariableName, orig))
	}()
	assert.NoError(t, os.Setenv(CLIModeVariableName, "helm"))
	assert.True(t, IsInHelmMode())
	assert.NoError(t, os.Setenv(CLIModeVariableName, "classic"))
	assert.False(t, IsInHelmMode())
	assert.NoError(t, os.Setenv(CLIModeVariableName, "random"))
	assert.True(t, IsInHelmMode())
}
