// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package checker

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeepEqualsCheck(t *testing.T) {
	names := []string{"a", "b"}
	type args struct {
		params []interface{}
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "args of basic type are equal",
			args: args{
				params: []interface{}{1, 1},
			},
			want: true,
		},
		{
			name: "args of basic type are not equal",
			args: args{
				params: []interface{}{1, 2},
			},
			want: false,
		},
		{
			name: "maps are deeply equal",
			args: args{
				params: []interface{}{
					map[string]string{
						"foo": "bar",
					},
					map[string]string{
						"foo": "bar",
					},
				},
			},
			want: true,
		},
		{
			name: "maps are not equal",
			args: args{
				params: []interface{}{
					map[string]string{
						"foo": "ar",
					},
					map[string]string{
						"foo": "bar",
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		equal, err := DeepEquals.Check(tt.args.params, names)
		require.Equal(t, tt.want, equal)
		require.Equal(t, equal, err == "")
	}

	equal, err := DeepEquals.Check([]interface{}{1, 1}, []string{"a"})
	require.False(t, equal)
	require.NotNil(t, err)

	equal, err = DeepEquals.Check([]interface{}{1}, []string{"a"})
	require.False(t, equal)
	require.NotNil(t, err)
}
