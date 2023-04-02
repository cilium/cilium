// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cidralloc

import (
	"errors"
	"testing"
)

func TestNewCIDRSets(t *testing.T) {
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
			wantErr: &ErrCIDRCollision{
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
			wantErr: &ErrCIDRCollision{
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
			_, err := NewCIDRSets(tt.args.isV6, tt.args.strCIDRs, tt.args.maskSize)
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
