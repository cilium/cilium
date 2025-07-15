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
		desc       string
		input      string
		validators []Validator
		target     map[string]string
		wantErr    string
		want       map[string]string
	}{
		{
			desc:   "no validator",
			input:  "k1= v1,k2=",
			target: make(map[string]string),
			want: map[string]string{
				"k1": " v1",
				"k2": "",
			},
		},
		{
			desc:   "validator that returns error",
			input:  "k1=v1,k2=v2",
			target: make(map[string]string),
			validators: []Validator{
				func(val string) error { return fmt.Errorf("invalid value %s", val) },
			},
			wantErr: "invalid value k1=v1",
		},
		{
			desc:  "multiple validators that return success",
			input: "k1=v1,k2=v2",
			validators: []Validator{
				func(val string) error { return nil },
				func(val string) error { return nil },
			},
			want: map[string]string{"k1": "v1", "k2": "v2"},
		},
		{
			desc:   "nil target map",
			input:  "k1=v1,k2=v2",
			target: nil,
			want:   map[string]string{"k1": "v1", "k2": "v2"},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			opts := NewMapOptions(&tc.target, tc.validators...)
			err := opts.Set(tc.input)
			if err != nil {
				if len(tc.wantErr) == 0 {
					t.Fatalf("NewMapOptions()=%v, want nil", err)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("NewMapOptions()=%v, want error with substring %q", err, tc.wantErr)
				}
				return
			} else if len(tc.wantErr) != 0 {
				t.Fatalf("NewMapOptions()=nil, want error with substring %q", tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, tc.target); diff != "" {
				t.Errorf("Unexpected result map (-want +got):\n%s", diff)
			}
		})
	}
}
