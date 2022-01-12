// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package install

import (
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/blang/semver/v4"
	"github.com/cilium/cilium/pkg/versioncheck"

	"github.com/cilium/cilium-cli/defaults"
)

func TestK8sInstaller_getCiliumVersion(t *testing.T) {
	defaultCiliumVersion, err := versioncheck.Version(strings.TrimPrefix(defaults.Version, "v"))
	if err != nil {
		t.Fatalf("failed to parse default Cilium version %q as semver", defaults.Version)
	}

	type fields struct{ params Parameters }
	tests := []struct {
		name   string
		fields fields
		want   semver.Version
	}{
		{
			name:   "default",
			fields: fields{Parameters{Writer: io.Discard}},
			want:   defaultCiliumVersion,
		},
		{
			name:   "version",
			fields: fields{Parameters{Writer: io.Discard, Version: "v9.9.99"}},
			want:   semver.Version{Major: 9, Minor: 9, Patch: 99},
		},
		{
			name:   "base-version",
			fields: fields{Parameters{Writer: io.Discard, Version: "random-version-string", BaseVersion: "v1.9.8"}},
			want:   semver.Version{Major: 1, Minor: 9, Patch: 8},
		},
		{
			name:   "random-version-without-base-version",
			fields: fields{Parameters{Writer: io.Discard, Version: "random-version-string"}},
			want:   defaultCiliumVersion,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &K8sInstaller{params: tt.fields.params}
			if got := k.getCiliumVersion(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getCiliumVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}
