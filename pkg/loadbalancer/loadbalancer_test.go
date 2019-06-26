// Copyright 2018 Authors of Cilium
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

package loadbalancer

import (
	"net"
	"testing"

	"gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	check.TestingT(t)
}

type TypesSuite struct{}

var _ = check.Suite(&TypesSuite{})

func TestL4Addr_Equals(t *testing.T) {
	type args struct {
		o *L4Addr
	}
	tests := []struct {
		name   string
		fields *L4Addr
		args   args
		want   bool
	}{
		{
			name: "both equal",
			fields: &L4Addr{
				Protocol: NONE,
				Port:     1,
			},
			args: args{
				o: &L4Addr{
					Protocol: NONE,
					Port:     1,
				},
			},
			want: true,
		},
		{
			name: "both different",
			fields: &L4Addr{
				Protocol: NONE,
				Port:     0,
			},
			args: args{
				o: &L4Addr{
					Protocol: NONE,
					Port:     1,
				},
			},
			want: false,
		},
		{
			name: "both nil",
			args: args{},
			want: true,
		},
		{
			name: "other nil",
			fields: &L4Addr{
				Protocol: NONE,
				Port:     1,
			},
			args: args{},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := tt.fields
			if got := l.Equals(tt.args.o); got != tt.want {
				t.Errorf("L4Addr.Equals() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFEPort_EqualsIgnoreID(t *testing.T) {
	type args struct {
		o *FEPort
	}
	tests := []struct {
		name   string
		fields *FEPort
		args   args
		want   bool
	}{
		{
			name: "both equal",
			fields: &FEPort{
				L4Addr: &L4Addr{
					Protocol: NONE,
					Port:     1,
				},
				ID: 1,
			},
			args: args{
				o: &FEPort{
					L4Addr: &L4Addr{
						Protocol: NONE,
						Port:     1,
					},
					ID: 1,
				},
			},
			want: true,
		},
		{
			name: "IDs different are considered equal",
			fields: &FEPort{
				L4Addr: &L4Addr{
					Protocol: NONE,
					Port:     1,
				},
				ID: 1,
			},
			args: args{
				o: &FEPort{
					L4Addr: &L4Addr{
						Protocol: NONE,
						Port:     1,
					},
					ID: 1001,
				},
			},
			want: true,
		},
		{
			name: "both nil",
			args: args{},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.fields
			if got := f.EqualsIgnoreID(tt.args.o); got != tt.want {
				t.Errorf("FEPort.EqualsIgnoreID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFEPort_Equals(t *testing.T) {
	type args struct {
		o *FEPort
	}
	tests := []struct {
		name   string
		fields *FEPort
		args   args
		want   bool
	}{
		{
			name: "both equal",
			fields: &FEPort{
				L4Addr: &L4Addr{
					Protocol: NONE,
					Port:     1,
				},
				ID: 1,
			},
			args: args{
				o: &FEPort{
					L4Addr: &L4Addr{
						Protocol: NONE,
						Port:     1,
					},
					ID: 1,
				},
			},
			want: true,
		},
		{
			name: "IDs different are considered different",
			fields: &FEPort{
				L4Addr: &L4Addr{
					Protocol: NONE,
					Port:     1,
				},
				ID: 1,
			},
			args: args{
				o: &FEPort{
					L4Addr: &L4Addr{
						Protocol: NONE,
						Port:     1,
					},
					ID: 1001,
				},
			},
			want: false,
		},
		{
			name: "both nil",
			args: args{},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.fields
			if got := f.Equals(tt.args.o); got != tt.want {
				t.Errorf("FEPort.Equals() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestL3n4AddrID_Equals(t *testing.T) {
	type args struct {
		o *L3n4AddrID
	}
	tests := []struct {
		name   string
		fields *L3n4AddrID
		args   args
		want   bool
	}{
		{
			name: "both equal",
			fields: &L3n4AddrID{
				L3n4Addr: L3n4Addr{
					L4Addr: L4Addr{
						Protocol: NONE,
						Port:     1,
					},
					IP: net.IPv4(1, 1, 1, 1),
				},
				ID: 1,
			},
			args: args{
				o: &L3n4AddrID{
					L3n4Addr: L3n4Addr{
						L4Addr: L4Addr{
							Protocol: NONE,
							Port:     1,
						},
						IP: net.IPv4(1, 1, 1, 1),
					},
					ID: 1,
				},
			},
			want: true,
		},
		{
			name: "IDs different",
			fields: &L3n4AddrID{
				L3n4Addr: L3n4Addr{
					L4Addr: L4Addr{
						Protocol: NONE,
						Port:     1,
					},
					IP: net.IPv4(1, 1, 1, 1),
				},
				ID: 1,
			},
			args: args{
				o: &L3n4AddrID{
					L3n4Addr: L3n4Addr{
						L4Addr: L4Addr{
							Protocol: NONE,
							Port:     1,
						},
						IP: net.IPv4(1, 1, 1, 1),
					},
					ID: 2,
				},
			},
			want: false,
		},
		{
			name: "IPs different",
			fields: &L3n4AddrID{
				L3n4Addr: L3n4Addr{
					L4Addr: L4Addr{
						Protocol: NONE,
						Port:     1,
					},
					IP: net.IPv4(2, 2, 2, 2),
				},
				ID: 1,
			},
			args: args{
				o: &L3n4AddrID{
					L3n4Addr: L3n4Addr{
						L4Addr: L4Addr{
							Protocol: NONE,
							Port:     1,
						},
						IP: net.IPv4(1, 1, 1, 1),
					},
					ID: 1,
				},
			},
			want: false,
		},
		{
			name: "Ports different",
			fields: &L3n4AddrID{
				L3n4Addr: L3n4Addr{
					L4Addr: L4Addr{
						Protocol: NONE,
						Port:     2,
					},
					IP: net.IPv4(1, 1, 1, 1),
				},
				ID: 1,
			},
			args: args{
				o: &L3n4AddrID{
					L3n4Addr: L3n4Addr{
						L4Addr: L4Addr{
							Protocol: NONE,
							Port:     1,
						},
						IP: net.IPv4(1, 1, 1, 1),
					},
					ID: 1,
				},
			},
			want: false,
		},
		{
			name: "both nil",
			args: args{},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.fields
			if got := f.Equals(tt.args.o); got != tt.want {
				t.Errorf("L3n4AddrID.Equals() = %v, want %v", got, tt.want)
			}
		})
	}
}
