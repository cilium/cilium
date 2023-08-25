// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"testing"

	check "github.com/cilium/checkmate"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
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
						Protocol: NONE,
						Port:     1,
					},
					AddrCluster: cmtypes.MustParseAddrCluster("1.1.1.1"),
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
						AddrCluster: cmtypes.MustParseAddrCluster("1.1.1.1"),
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
					AddrCluster: cmtypes.MustParseAddrCluster("1.1.1.1"),
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
						AddrCluster: cmtypes.MustParseAddrCluster("1.1.1.1"),
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
					AddrCluster: cmtypes.MustParseAddrCluster("2.2.2.2"),
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
						AddrCluster: cmtypes.MustParseAddrCluster("1.1.1.1"),
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
					AddrCluster: cmtypes.MustParseAddrCluster("1.1.1.1"),
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
						AddrCluster: cmtypes.MustParseAddrCluster("1.1.1.1"),
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
		svcExtLocal bool
		svcIntLocal bool
		svcRoutable bool
		svcL7LB     bool
	}
	tests := []struct {
		name string
		args args
		want ServiceFlags
	}{
		{
			args: args{
				svcType:     SVCTypeClusterIP,
				svcExtLocal: false,
				svcIntLocal: false,
				svcRoutable: true,
			},
			want: serviceFlagNone | serviceFlagRoutable,
		},
		{
			args: args{
				svcType:     SVCTypeNodePort,
				svcExtLocal: false,
				svcIntLocal: false,
				svcRoutable: true,
			},
			want: serviceFlagNodePort | serviceFlagRoutable,
		},
		{
			args: args{
				svcType:     SVCTypeExternalIPs,
				svcExtLocal: false,
				svcIntLocal: false,
				svcRoutable: true,
			},
			want: serviceFlagExternalIPs | serviceFlagRoutable,
		},
		{
			// Impossible combination, ClusterIP can't have externalTrafficPolicy=Local.
			args: args{
				svcType:     SVCTypeClusterIP,
				svcExtLocal: true,
				svcIntLocal: false,
				svcRoutable: true,
			},
			want: serviceFlagNone | serviceFlagExtLocalScope | serviceFlagRoutable,
		},
		{
			args: args{
				svcType:     SVCTypeNodePort,
				svcExtLocal: true,
				svcIntLocal: false,
				svcRoutable: true,
			},
			want: serviceFlagNodePort | serviceFlagExtLocalScope | serviceFlagTwoScopes | serviceFlagRoutable,
		},
		{
			args: args{
				svcType:     SVCTypeExternalIPs,
				svcExtLocal: true,
				svcIntLocal: false,
				svcRoutable: true,
			},
			want: serviceFlagExternalIPs | serviceFlagExtLocalScope | serviceFlagTwoScopes | serviceFlagRoutable,
		},
		{
			args: args{
				svcType:     SVCTypeClusterIP,
				svcExtLocal: false,
				svcIntLocal: true,
				svcRoutable: true,
			},
			want: serviceFlagNone | serviceFlagIntLocalScope | serviceFlagRoutable,
		},
		{
			args: args{
				svcType:     SVCTypeNodePort,
				svcExtLocal: false,
				svcIntLocal: true,
				svcRoutable: true,
			},
			want: serviceFlagNodePort | serviceFlagIntLocalScope | serviceFlagTwoScopes | serviceFlagRoutable,
		},
		{
			args: args{
				svcType:     SVCTypeExternalIPs,
				svcExtLocal: false,
				svcIntLocal: true,
				svcRoutable: true,
			},
			want: serviceFlagExternalIPs | serviceFlagIntLocalScope | serviceFlagTwoScopes | serviceFlagRoutable,
		},
		{
			// Impossible combination, ClusterIP can't have externalTrafficPolicy=Local.
			args: args{
				svcType:     SVCTypeClusterIP,
				svcExtLocal: true,
				svcIntLocal: true,
				svcRoutable: true,
			},
			want: serviceFlagNone | serviceFlagExtLocalScope | serviceFlagIntLocalScope | serviceFlagRoutable,
		},
		{
			args: args{
				svcType:     SVCTypeNodePort,
				svcExtLocal: true,
				svcIntLocal: true,
				svcRoutable: true,
			},
			want: serviceFlagNodePort | serviceFlagExtLocalScope | serviceFlagIntLocalScope | serviceFlagRoutable,
		},
		{
			args: args{
				svcType:     SVCTypeExternalIPs,
				svcExtLocal: true,
				svcIntLocal: true,
				svcRoutable: true,
			},
			want: serviceFlagExternalIPs | serviceFlagExtLocalScope | serviceFlagIntLocalScope | serviceFlagRoutable,
		},
		{
			args: args{
				svcType:     SVCTypeExternalIPs,
				svcExtLocal: true,
				svcIntLocal: false,
				svcRoutable: false,
			},
			want: serviceFlagExternalIPs | serviceFlagExtLocalScope | serviceFlagTwoScopes,
		},
		{
			args: args{
				svcType:     SVCTypeExternalIPs,
				svcExtLocal: false,
				svcIntLocal: true,
				svcRoutable: false,
			},
			want: serviceFlagExternalIPs | serviceFlagIntLocalScope | serviceFlagTwoScopes,
		},
		{
			args: args{
				svcType:     SVCTypeExternalIPs,
				svcExtLocal: true,
				svcIntLocal: true,
				svcRoutable: false,
			},
			want: serviceFlagExternalIPs | serviceFlagExtLocalScope | serviceFlagIntLocalScope,
		},
		{
			args: args{
				svcType:     SVCTypeLocalRedirect,
				svcExtLocal: false,
				svcIntLocal: false,
				svcRoutable: true,
			},
			want: serviceFlagLocalRedirect | serviceFlagRoutable,
		},
		{
			args: args{
				svcType: SVCTypeClusterIP,
				svcL7LB: true,
			},
			want: serviceFlagL7LoadBalancer,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &SvcFlagParam{
				SvcExtLocal:     tt.args.svcExtLocal,
				SvcIntLocal:     tt.args.svcIntLocal,
				SessionAffinity: false,
				IsRoutable:      tt.args.svcRoutable,
				SvcType:         tt.args.svcType,
				L7LoadBalancer:  tt.args.svcL7LB,
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
			s:    serviceFlagNodePort | serviceFlagExtLocalScope | serviceFlagRoutable,
			want: "NodePort, Local",
		},
		{
			name: "Test-4",
			s:    serviceFlagExternalIPs | serviceFlagExtLocalScope | serviceFlagRoutable,
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
		{
			name: "Test-7",
			s:    serviceFlagNodePort | serviceFlagIntLocalScope | serviceFlagRoutable,
			want: "NodePort, InternalLocal",
		},
		{
			name: "Test-8",
			s:    serviceFlagExternalIPs | serviceFlagIntLocalScope | serviceFlagRoutable,
			want: "ExternalIPs, InternalLocal",
		},
		{
			name: "Test-9",
			s:    serviceFlagNodePort | serviceFlagExtLocalScope | serviceFlagIntLocalScope | serviceFlagRoutable,
			want: "NodePort, Local, InternalLocal",
		},
		{
			name: "Test-10",
			s:    serviceFlagExternalIPs | serviceFlagExtLocalScope | serviceFlagIntLocalScope | serviceFlagRoutable,
			want: "ExternalIPs, Local, InternalLocal",
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
	addr := NewL3n4Addr(TCP, cmtypes.MustParseAddrCluster("1.2.3.4"), 8080, ScopeInternal)
	benchmarkHash(b, addr)
}

func BenchmarkL3n4Addr_Hash_IPv6_Short(b *testing.B) {
	addr := NewL3n4Addr(TCP, cmtypes.MustParseAddrCluster("fd00::1:36c6"), 8080, ScopeInternal)
	benchmarkHash(b, addr)
}

func BenchmarkL3n4Addr_Hash_IPv6_Long(b *testing.B) {
	addr := NewL3n4Addr(TCP, cmtypes.MustParseAddrCluster("2001:0db8:85a3::8a2e:0370:7334"), 8080, ScopeInternal)
	benchmarkHash(b, addr)
}

func BenchmarkL3n4Addr_Hash_IPv6_Max(b *testing.B) {
	addr := NewL3n4Addr(TCP, cmtypes.MustParseAddrCluster("1020:3040:5060:7080:90a0:b0c0:d0e0:f000"), 30303, 100)
	benchmarkHash(b, addr)
}
