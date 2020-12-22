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

package clusterpool

import (
	"errors"
	"testing"
)

func Test_newCIDRSets(t *testing.T) {
	type args struct {
		isV6     bool
		strCIDRs []string
		maskSize int
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name: "test-1",
			args: args{
				isV6:     false,
				strCIDRs: []string{"10.0.0.0/16"},
				maskSize: 24,
			},
			wantErr: nil,
		},
		{
			name: "test-2 - CIDRs collide",
			args: args{
				isV6:     false,
				strCIDRs: []string{"10.0.0.0/16", "10.0.0.0/8"},
				maskSize: 24,
			},
			wantErr: &ErrCIDRColision{
				cidr: "10.0.0.0/8",
			},
		},
		{
			name: "test-2 - CIDRs collide",
			args: args{
				isV6:     false,
				strCIDRs: []string{"10.0.0.0/8"},
				maskSize: 24,
			},
			wantErr: nil,
		},
		{
			name: "test-4 - CIDRs collide",
			args: args{
				isV6:     true,
				strCIDRs: []string{"fd00::/100", "fd00::/96"},
				maskSize: 112,
			},
			wantErr: &ErrCIDRColision{
				cidr: "fd00::/96",
			},
		},
		{
			name: "test-5 - CIDRs do not collide",
			args: args{
				isV6:     true,
				strCIDRs: []string{"fd00::/100", "fd00::1:0000:0000/96"},
				maskSize: 112,
			},
			wantErr: nil,
		},
		{
			name: "test-6 - CIDR does not collide",
			args: args{
				isV6:     true,
				strCIDRs: []string{"fd00::/104"},
				maskSize: 120,
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newCIDRSets(tt.args.isV6, tt.args.strCIDRs, tt.args.maskSize)
			if (err != nil) != (tt.wantErr != nil) {
				t.Errorf("newCIDRSets() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("newCIDRSets() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
