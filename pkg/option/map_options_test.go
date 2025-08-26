// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestMapOptions(t *testing.T) {
	for _, tc := range []struct {
		desc      string
		input     string
		validator Validator
		wantErr   string
		want      map[string]string
	}{
		{
			desc:  "no validator",
			input: "k1= v1,k2=",
			want: map[string]string{
				"k1": " v1",
				"k2": "",
			},
		},
		{
			desc:  "validator that returns error",
			input: "k1=v1,k2=v2",
			validator: func(val string) (string, error) {
				return "", fmt.Errorf("invalid value %s", val)
			},
			wantErr: "invalid value k1=v1",
		},
		{
			desc:  "validator that modifies entries",
			input: "k8s:k1 =v1,k8s:k2= v2",
			validator: func(val string) (string, error) {
				val = strings.TrimPrefix(val, "k8s:")
				vals := strings.SplitN(val, "=", 2)
				kv := []string{strings.TrimSpace(vals[0]), strings.TrimSpace(vals[1])}
				return strings.Join(kv, "="), nil
			},
			want: map[string]string{
				"k1": "v1",
				"k2": "v2",
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			opts := NewNamedMapOptions("flag-1", &map[string]string{}, tc.validator)
			err := opts.Set(tc.input)
			if err != nil {
				if len(tc.wantErr) == 0 {
					t.Fatalf("NewNamedMapOptions()=%v, want nil", err)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("NewNamedMapOptions()=%v, want error with substring %q", err, tc.wantErr)
				}
				return
			} else if len(tc.wantErr) != 0 {
				t.Fatalf("NewNamedMapOptions()=nil, want error with substring %q", tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, opts.vals); diff != "" {
				t.Errorf("Unexpected result map (-want +got):\n%s", diff)
			}
		})
	}
}
