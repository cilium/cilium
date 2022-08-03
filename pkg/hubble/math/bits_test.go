// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package math

import (
	"testing"
)

func Test_msb(t *testing.T) {
	type args struct {
		x uint64
	}
	tests := []struct {
		name string
		args args
		want uint8
	}{
		{
			args: args{
				x: 0,
			},
			want: 0,
		},
		{
			args: args{
				x: 0x10,
			},
			want: 5,
		},
		{
			args: args{
				x: 0x1FF,
			},
			want: 9,
		},
		{
			args: args{
				x: ^uint64(0),
			},
			want: 64,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MSB(tt.args.x); got != tt.want {
				t.Errorf("MSB() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getmask(t *testing.T) {
	type args struct {
		x uint8
	}
	tests := []struct {
		name string
		args args
		want uint64
	}{
		{
			args: args{
				1,
			},
			want: 0x1,
		},
		{
			args: args{
				0,
			},
			want: 0x0,
		},
		{
			args: args{
				2,
			},
			// 0011
			want: 0x3,
		},
		{
			args: args{
				3,
			},
			// 0111
			want: 0x7,
		},
		{
			args: args{
				64,
			},
			want: ^uint64(0),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetMask(tt.args.x); got != tt.want {
				t.Errorf("GetMask() = %v, want %v", got, tt.want)
			}
		})
	}
}
