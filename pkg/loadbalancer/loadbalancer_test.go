// Copyright 2018-2019 Authors of Cilium
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
				Protocol: TCP,
				Port:     1,
			},
			args: args{
				o: &L4Addr{
					Protocol: TCP,
					Port:     1,
				},
			},
			want: true,
		},
		{
			name: "both different",
			fields: &L4Addr{
				Protocol: TCP,
				Port:     0,
			},
			args: args{
				o: &L4Addr{
					Protocol: TCP,
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
				Protocol: TCP,
				Port:     1,
			},
			args: args{},
			want: false,
		},
		{
			name: "protocol different",
			fields: &L4Addr{
				Protocol: TCP,
				Port:     1,
			},
			args: args{
				o: &L4Addr{
					Protocol: UDP,
					Port:     1,
				},
			},
			want: false,
		},
		{
			name: "protocol different one is none",
			fields: &L4Addr{
				Protocol: TCP,
				Port:     1,
			},
			args: args{
				o: &L4Addr{
					Protocol: NONE,
					Port:     1,
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := tt.fields
			if got := l.DeepEqual(tt.args.o); got != tt.want {
				t.Errorf("L4Addr.DeepEqual() = %v, want %v", got, tt.want)
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
						Protocol: TCP,
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
							Protocol: TCP,
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
						Protocol: TCP,
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
							Protocol: TCP,
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
						Protocol: TCP,
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
							Protocol: TCP,
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
						Protocol: TCP,
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
							Protocol: TCP,
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
			name: "protocols different",
			fields: &L3n4AddrID{
				L3n4Addr: L3n4Addr{
					L4Addr: L4Addr{
						Protocol: TCP,
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
							Protocol: UDP,
							Port:     2,
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
			if got := f.DeepEqual(tt.args.o); got != tt.want {
				t.Errorf("L3n4AddrID.Equals() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewSvcFlag(t *testing.T) {
	type args struct {
		svcType     SVCType
		svcLocal    bool
		svcRoutable bool
	}
	tests := []struct {
		name string
		args args
		want ServiceFlags
	}{
		{
			args: args{
				svcType:     SVCTypeClusterIP,
				svcLocal:    false,
				svcRoutable: true,
			},
			want: serviceFlagNone | serviceFlagRoutable,
		},
		{
			args: args{
				svcType:     SVCTypeNodePort,
				svcLocal:    false,
				svcRoutable: true,
			},
			want: serviceFlagNodePort | serviceFlagRoutable,
		},
		{
			args: args{
				svcType:     SVCTypeExternalIPs,
				svcLocal:    false,
				svcRoutable: true,
			},
			want: serviceFlagExternalIPs | serviceFlagRoutable,
		},
		{
			args: args{
				svcType:     SVCTypeClusterIP,
				svcLocal:    true,
				svcRoutable: true,
			},
			want: serviceFlagNone | serviceFlagLocalScope | serviceFlagRoutable,
		},
		{
			args: args{
				svcType:     SVCTypeNodePort,
				svcLocal:    true,
				svcRoutable: true,
			},
			want: serviceFlagNodePort | serviceFlagLocalScope | serviceFlagRoutable,
		},
		{
			args: args{
				svcType:     SVCTypeExternalIPs,
				svcLocal:    true,
				svcRoutable: true,
			},
			want: serviceFlagExternalIPs | serviceFlagLocalScope | serviceFlagRoutable,
		},
		{
			args: args{
				svcType:     SVCTypeExternalIPs,
				svcLocal:    true,
				svcRoutable: false,
			},
			want: serviceFlagExternalIPs | serviceFlagLocalScope,
		},
		{
			args: args{
				svcType:     SVCTypeLocalRedirect,
				svcLocal:    false,
				svcRoutable: true,
			},
			want: serviceFlagLocalRedirect | serviceFlagRoutable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &SvcFlagParam{
				SvcLocal:        tt.args.svcLocal,
				SessionAffinity: false,
				IsRoutable:      tt.args.svcRoutable,
				SvcType:         tt.args.svcType,
			}
			if got := NewSvcFlag(p); got != tt.want {
				t.Errorf("NewSvcFlag() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServiceFlags_String(t *testing.T) {
	tests := []struct {
		name string
		s    ServiceFlags
		want string
	}{
		{
			name: "Test-1",
			s:    serviceFlagExternalIPs | serviceFlagRoutable,
			want: "ExternalIPs",
		},
		{
			name: "Test-2",
			s:    serviceFlagNone | serviceFlagRoutable,
			want: "ClusterIP",
		},
		{
			name: "Test-3",
			s:    serviceFlagNodePort | serviceFlagLocalScope | serviceFlagRoutable,
			want: "NodePort, Local",
		},
		{
			name: "Test-4",
			s:    serviceFlagExternalIPs | serviceFlagLocalScope | serviceFlagRoutable,
			want: "ExternalIPs, Local",
		},
		{
			name: "Test-5",
			s:    serviceFlagLoadBalancer | serviceFlagRoutable,
			want: "LoadBalancer",
		},
		{
			name: "Test-6",
			s:    serviceFlagLoadBalancer,
			want: "LoadBalancer, non-routable",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func benchmarkHash(b *testing.B, addr *L3n4Addr) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		addr.Hash()
	}
}

func BenchmarkL3n4Addr_Hash_IPv4(b *testing.B) {
	addr := NewL3n4Addr(TCP, net.IPv4(1, 2, 3, 4), 8080, ScopeInternal)
	benchmarkHash(b, addr)
}

func BenchmarkL3n4Addr_Hash_IPv4_4bytes(b *testing.B) {
	addr := NewL3n4Addr(TCP, net.IPv4(1, 2, 3, 4).To4(), 8080, ScopeInternal)
	benchmarkHash(b, addr)
}

func BenchmarkL3n4Addr_Hash_IPv6_Short(b *testing.B) {
	addr := NewL3n4Addr(TCP, net.ParseIP("fd00::1:36c6"), 8080, ScopeInternal)
	benchmarkHash(b, addr)
}

func BenchmarkL3n4Addr_Hash_IPv6_Long(b *testing.B) {
	addr := NewL3n4Addr(TCP, net.ParseIP("2001:0db8:85a3::8a2e:0370:7334"), 8080, ScopeInternal)
	benchmarkHash(b, addr)
}

func BenchmarkL3n4Addr_Hash_IPv6_Max(b *testing.B) {
	addr := NewL3n4Addr(TCP, net.ParseIP("1020:3040:5060:7080:90a0:b0c0:d0e0:f000"), 30303, 100)
	benchmarkHash(b, addr)
}
