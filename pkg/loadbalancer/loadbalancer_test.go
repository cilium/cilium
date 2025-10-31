// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
)

func TestL4Addr_Equals(t *testing.T) {
	type args struct {
		o L4Addr
	}
	tests := []struct {
		name   string
		fields L4Addr
		args   args
		want   bool
	}{
		{
			name: "both equal",
			fields: L4Addr{
				Protocol: NONE,
				Port:     1,
			},
			args: args{
				o: L4Addr{
					Protocol: NONE,
					Port:     1,
				},
			},
			want: true,
		},
		{
			name: "both different",
			fields: L4Addr{
				Protocol: NONE,
				Port:     0,
			},
			args: args{
				o: L4Addr{
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
			fields: L4Addr{
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
				t.Errorf("L4Addr.DeepEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestL3n4Addr_DeepEqual(t *testing.T) {
	var v4, v6 L3n4Addr
	require.NoError(t, v4.ParseFromString("1.1.1.1:80/TCP"))
	require.NoError(t, v6.ParseFromString("[2001::1]:80/TCP"))

	assert.True(t, v4.DeepEqual(&v4))
	assert.True(t, v6.DeepEqual(&v6))
	assert.False(t, v4.DeepEqual(&v6))
	assert.False(t, v6.DeepEqual(&v4))

	var nilp *L3n4Addr
	assert.True(t, nilp.DeepEqual(nil))
	assert.False(t, nilp.DeepEqual(&v4))

	var v4_2, v6_2 L3n4Addr
	require.NoError(t, v4_2.ParseFromString("1.1.1.1:80/TCP"))
	require.NoError(t, v6_2.ParseFromString("[2001::1]:80/TCP"))

	assert.True(t, v4.DeepEqual(&v4_2))
	assert.True(t, v6.DeepEqual(&v6_2))
}

func TestL3n4Addr_Bytes(t *testing.T) {
	v4 := cmtypes.MustParseAddrCluster("1.1.1.1")
	v4c3 := cmtypes.MustParseAddrCluster("1.1.1.1@3")
	v6 := cmtypes.MustParseAddrCluster("2001::1")
	tests := []struct {
		addr     L3n4Addr
		expected []byte
	}{
		{
			addr: NewL3n4Addr(
				NONE,
				v4,
				0xabcd,
				ScopeExternal,
			),
			expected: []byte{
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 1, 1, 1, 1, // IP
				0, 0, 0, 0, // Cluster 0
				0xab, 0xcd, // Port
				'?', // L4Type
				0,   // Scope
			},
		},
		{
			addr: NewL3n4Addr(
				TCP,
				v4c3,
				0xabcd,
				ScopeInternal,
			),
			expected: []byte{
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 1, 1, 1, 1, // IP
				0, 0, 0, 3, // Cluster 3
				0xab, 0xcd, // Port
				'T', // L4Type
				1,   // Scope
			},
		},
		{
			addr: NewL3n4Addr(
				UDP,
				v6,
				0xaabb,
				ScopeExternal,
			),
			expected: []byte{
				32, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // IP
				0, 0, 0, 0, // Cluster 0
				0xaa, 0xbb, // Port
				'U', // L4Type
				0,   // Scope
			},
		},
	}

	for _, test := range tests {
		if !bytes.Equal(test.addr.Bytes(), test.expected) {
			t.Errorf("L3n4Addr.Bytes() = %v, want %v", test.addr.Bytes(), test.expected)
		}
	}
}

func TestL3n4AddrYAML(t *testing.T) {
	tests := []string{
		"0.0.0.0:0/TCP",
		"1.1.1.1:1/UDP",
		"1.1.1.1:65535/UDP",
		"[2001::1]:80/TCP",
		"[2001::1]:80/SCTP",
	}
	for _, test := range tests {
		var l L3n4Addr
		if assert.NoError(t, l.ParseFromString(test), "parse %q", test) {
			out, err := yaml.Marshal(l)
			if assert.NoError(t, err, "Marshal %+v", l) {
				assert.Equal(t, strings.Trim(string(out), "\n'"), test)
				var l2 L3n4Addr
				assert.NoError(t, yaml.Unmarshal(out, &l2))
				assert.Equal(t, l, l2)
			}
		}
	}
}

func TestL3n4Addr_Strings(t *testing.T) {
	tests := []struct {
		name               string
		fields             L3n4Addr
		string             string
		stringWithProtocol string
	}{
		{
			name: "IPv4 no protocol",
			fields: NewL3n4Addr(
				NONE,
				cmtypes.MustParseAddrCluster("1.1.1.1"),
				9876,
				ScopeExternal,
			),
			string:             "1.1.1.1:9876/NONE",
			stringWithProtocol: "1.1.1.1:9876/NONE",
		},
		{
			name: "IPv4 TCP",
			fields: NewL3n4Addr(
				TCP,
				cmtypes.MustParseAddrCluster("2.2.2.2"),
				9876,
				ScopeExternal,
			),
			string:             "2.2.2.2:9876/TCP",
			stringWithProtocol: "2.2.2.2:9876/TCP",
		},
		{
			name: "IPv4 UDP",
			fields: NewL3n4Addr(
				UDP,
				cmtypes.MustParseAddrCluster("3.3.3.3"),
				9876,
				ScopeInternal,
			),
			string:             "3.3.3.3:9876/UDP/i",
			stringWithProtocol: "3.3.3.3:9876/UDP/i",
		},
		{
			name: "IPv4 SCTP",
			fields: NewL3n4Addr(
				SCTP,
				cmtypes.MustParseAddrCluster("4.4.4.4"),
				9876,
				ScopeExternal,
			),
			string:             "4.4.4.4:9876/SCTP",
			stringWithProtocol: "4.4.4.4:9876/SCTP",
		},
		{
			name: "IPv6 no protocol",
			fields: NewL3n4Addr(
				NONE,
				cmtypes.MustParseAddrCluster("1020:3040:5060:7080:90a0:b0c0:d0e0:f000"),
				9876,
				ScopeExternal,
			),
			string:             "[1020:3040:5060:7080:90a0:b0c0:d0e0:f000]:9876/NONE",
			stringWithProtocol: "[1020:3040:5060:7080:90a0:b0c0:d0e0:f000]:9876/NONE",
		},
		{
			name: "IPv6 TCP",
			fields: NewL3n4Addr(
				TCP,
				cmtypes.MustParseAddrCluster("1020:3040:5060:7080:90a0:b0c0:d0e0:f000"),
				9876,
				ScopeExternal,
			),
			string:             "[1020:3040:5060:7080:90a0:b0c0:d0e0:f000]:9876/TCP",
			stringWithProtocol: "[1020:3040:5060:7080:90a0:b0c0:d0e0:f000]:9876/TCP",
		},
		{
			name: "IPv6 UDP",
			fields: NewL3n4Addr(
				UDP,
				cmtypes.MustParseAddrCluster("1020:3040:5060:7080:90a0:b0c0:d0e0:f000"),
				9876,
				ScopeInternal,
			),
			string:             "[1020:3040:5060:7080:90a0:b0c0:d0e0:f000]:9876/UDP/i",
			stringWithProtocol: "[1020:3040:5060:7080:90a0:b0c0:d0e0:f000]:9876/UDP/i",
		},
		{
			name: "IPv6 SCTP",
			fields: NewL3n4Addr(
				SCTP,
				cmtypes.MustParseAddrCluster("1020:3040:5060:7080:90a0:b0c0:d0e0:f000"),
				9876,
				ScopeExternal,
			),
			string:             "[1020:3040:5060:7080:90a0:b0c0:d0e0:f000]:9876/SCTP",
			stringWithProtocol: "[1020:3040:5060:7080:90a0:b0c0:d0e0:f000]:9876/SCTP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.fields
			string := f.String()
			if string != tt.string {
				t.Errorf("L3n4AddrID.String() = %s, want %s", string, tt.string)
			}
			strWithProtocol := f.StringWithProtocol()
			if strWithProtocol != tt.stringWithProtocol {
				t.Errorf("L3n4AddrID.StringWithProtocol() = %s, want %s", strWithProtocol, tt.stringWithProtocol)
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

func TestServiceName(t *testing.T) {
	n := NewServiceName("", "")
	n2 := NewServiceName("", "")
	assert.Equal(t, "/", n.String())
	assert.True(t, n.Equal(n2))

	n = NewServiceName("foo", "bar")
	n2 = NewServiceName("foo", "bar")
	assert.Equal(t, "foo/bar", n.String())
	assert.Equal(t, "foo/bar", string(n.Key()))
	assert.Equal(t, "foo", n.Namespace())
	assert.Equal(t, "bar", n.Name())
	assert.True(t, n.Equal(n2))
	n2 = NewServiceName("foo", "baz")
	assert.False(t, n.Equal(n2))

	n = NewServiceNameInCluster("foo", "bar", "quux")
	assert.Equal(t, "foo/bar/quux", n.String())
	assert.Equal(t, "foo", n.Cluster())
	assert.Equal(t, "bar", n.Namespace())
	assert.Equal(t, "quux", n.Name())
	assert.Equal(t, "foo/bar/quux", string(n.Key()))
	assert.False(t, n.Equal(n2))

}

func TestServiceNameYAMLJSON(t *testing.T) {
	tests := []struct {
		name ServiceName
		want string
	}{
		{
			name: NewServiceName("", "foo"),
			want: "/foo",
		},
		{
			name: NewServiceName("bar", "foo"),
			want: "bar/foo",
		},
		{
			name: NewServiceNameInCluster("quux", "bar", "foo"),
			want: "quux/bar/foo",
		},
	}
	for _, test := range tests {
		out, err := yaml.Marshal(test.name)
		if assert.NoError(t, err, "Marshal") {
			s := strings.TrimSpace(string(out))
			assert.Equal(t, test.want, s)

			var name ServiceName
			err := yaml.Unmarshal(out, &name)
			if assert.NoError(t, err, "Unmarshal") {
				assert.Equal(t, test.name.Name(), name.Name(), "Name %v, namePos %d", name, name.namePos)
				assert.Equal(t, test.name.Namespace(), name.Namespace(), "Namespace %v, clusterEndPos", name, name.clusterEndPos)
				assert.Equal(t, test.name.Cluster(), name.Cluster(), "Cluster %v, clusterEndPos %v", name, name.clusterEndPos)
				assert.True(t, test.name.Equal(name), "Equal %v %v", test.name, name)
			}
		}

		out, err = json.Marshal(test.name)
		if assert.NoError(t, err, "Marshal") {
			s := string(out)
			assert.Equal(t, `"`+test.want+`"`, s)

			var name ServiceName
			err := json.Unmarshal(out, &name)
			if assert.NoError(t, err, "Unmarshal") {
				assert.Equal(t, test.name.Name(), name.Name(), "Name %v, namePos %d", name, name.namePos)
				assert.Equal(t, test.name.Namespace(), name.Namespace(), "Namespace %v, clusterEndPos", name, name.clusterEndPos)
				assert.Equal(t, test.name.Cluster(), name.Cluster(), "Cluster %v, clusterEndPos %v", name, name.clusterEndPos)
				assert.True(t, test.name.Equal(name), "Equal %v %v", test.name, name)
			}
		}
	}
}

func TestL4AddrParsing(t *testing.T) {
	type testCase struct {
		err    bool
		input  string
		output L4Addr
	}

	testCases := []testCase{
		{false, "443/tcp", L4Addr{Protocol: TCP, Port: 443}},
		{false, "1312/udp", L4Addr{Protocol: UDP, Port: 1312}},
		{true, "65538/tcp", L4Addr{}}, // port > 16 bits
		{true, "123/abcd", L4Addr{}},  // unknown proto
	}

	for _, tc := range testCases {
		addr, err := L4AddrFromString(tc.input)
		if tc.err {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			// test the conversion back
			require.Equal(t, addr.String(), strings.ToUpper(tc.input))
		}

		require.Equal(t, tc.output, addr)
	}
}

func BenchmarkNewServiceName(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		NewServiceNameInCluster("foo", "bar", "baz")
	}
}

func BenchmarkServiceNameKey(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if len(NewServiceNameInCluster("foo", "bar", "baz").Key()) == 0 {
			// Do something so this won't be optimized out.
			b.Fatalf("empty length")
		}
	}
}

func benchmarkString(b *testing.B, addr L3n4Addr) {
	b.ReportAllocs()

	var length int
	for b.Loop() {
		length += len(addr.String())
	}
}

func BenchmarkL3n4Addr_String_IPv4(b *testing.B) {
	addr := NewL3n4Addr(TCP, cmtypes.MustParseAddrCluster("192.168.123.210"), 8080, ScopeInternal)
	benchmarkString(b, addr)
}

func BenchmarkL3n4Addr_String_IPv6_Max(b *testing.B) {
	addr := NewL3n4Addr(TCP, cmtypes.MustParseAddrCluster("1020:3040:5060:7080:90a0:b0c0:d0e0:f000"), 30303, 100)
	benchmarkString(b, addr)
}

func benchmarkStringWithProtocol(b *testing.B, addr L3n4Addr) {
	b.ReportAllocs()

	for b.Loop() {
		addr.StringWithProtocol()
	}
}

func BenchmarkL3n4Addr_StringWithProtocol_IPv4(b *testing.B) {
	addr := NewL3n4Addr(TCP, cmtypes.MustParseAddrCluster("192.168.123.210"), 8080, ScopeInternal)
	benchmarkStringWithProtocol(b, addr)
}

func BenchmarkL3n4Addr_StringWithProtocol_IPv6_Max(b *testing.B) {
	addr := NewL3n4Addr(TCP, cmtypes.MustParseAddrCluster("1020:3040:5060:7080:90a0:b0c0:d0e0:f000"), 30303, 100)
	benchmarkStringWithProtocol(b, addr)
}
