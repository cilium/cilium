// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package install

import (
	"io"
	"reflect"
	"testing"

	"github.com/blang/semver/v4"
)

func TestK8sInstaller_getCiliumVersion(t *testing.T) {
	type fields struct{ params Parameters }
	tests := []struct {
		name   string
		fields fields
		want   semver.Version
	}{
		{
			name:   "default",
			fields: fields{Parameters{Writer: io.Discard}},
			want:   semver.Version{Major: 1, Minor: 10, Patch: 0},
		},
		{
			name:   "version",
			fields: fields{Parameters{Writer: io.Discard, Version: "v1.10.3"}},
			want:   semver.Version{Major: 1, Minor: 10, Patch: 3},
		},
		{
			name:   "base-version",
			fields: fields{Parameters{Writer: io.Discard, Version: "random-version-string", BaseVersion: "v1.9.8"}},
			want:   semver.Version{Major: 1, Minor: 9, Patch: 8},
		},
		{
			name:   "random-version-without-base-version",
			fields: fields{Parameters{Writer: io.Discard, Version: "random-version-string"}},
			want:   semver.Version{Major: 1, Minor: 10, Patch: 0},
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
