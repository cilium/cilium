// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package build

import (
	"testing"

	"github.com/blang/semver/v4"
	"github.com/stretchr/testify/assert"
)

func TestVersion(t *testing.T) {
	tests := []struct {
		component, core, revision string
		want                      string
	}{
		{
			component: "hubble-relay",
			core:      "1.9.0",
			revision:  "63aa1b8",
			want:      "hubble-relay v1.9.0+g63aa1b8",
		}, {
			component: "hubble-relay",
			core:      "1.9.0-rc3",
			revision:  "9907232",
			want:      "hubble-relay v1.9.0-rc3+g9907232",
		}, {
			component: "hubble-relay",
			core:      "1.9.0",
			revision:  "",
			want:      "hubble-relay v1.9.0",
		}, {
			component: "hubble-relay",
			core:      "",
			revision:  "",
			want:      "hubble-relay",
		},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			v := &Version{
				component: tt.component,
				Core:      tt.core,
				Revision:  tt.revision,
			}
			assert.Equal(t, tt.want, v.String())
			if canonical := v.SemVer(); canonical != "" {
				_, err := semver.Parse(canonical)
				assert.NoError(t, err)
			}
		})
	}
}
