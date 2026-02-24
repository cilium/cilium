// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package template

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRender(t *testing.T) {
	type args struct {
		data any
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "trim suffix",
			args: args{
				data: struct {
					ExternalTarget string
				}{
					ExternalTarget: "one.one.one.one.",
				},
			},
		},
		{
			name: "ip to cidr",
			args: args{
				data: struct {
					ExternalCIDR string
					ExternalIP   string
				}{
					ExternalCIDR: "10.0.0.0/16",
					ExternalIP:   "10.0.0.2",
				},
			},
		},
		{
			name: "wildcard prefix",
			args: args{
				data: struct {
					ExternalTarget string
				}{
					ExternalTarget: "one.one.one.one.",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testDir := fmt.Sprintf("testdata/%s", strings.ReplaceAll(tt.name, " ", "_"))
			tmpl, err := os.ReadFile(fmt.Sprintf("%s/in.yaml", testDir))
			require.NoError(t, err)

			got, err := Render(string(tmpl), tt.args.data)
			require.NoError(t, err)

			expected, err := os.ReadFile(fmt.Sprintf("%s/out.yaml", testDir))
			require.NoError(t, err)
			require.YAMLEq(t, string(expected), got)
		})
	}
}
