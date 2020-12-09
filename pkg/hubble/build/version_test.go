// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

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
