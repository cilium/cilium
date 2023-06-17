// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identity

import (
	"net"
	"net/netip"
	"testing"

	. "github.com/cilium/checkmate"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labels/cidr"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type IdentityTestSuite struct{}

var _ = Suite(&IdentityTestSuite{})

func (s *IdentityTestSuite) TestReservedID(c *C) {
	i := GetReservedID("host")
	c.Assert(i, Equals, NumericIdentity(1))
	c.Assert(i.String(), Equals, "host")

	i = GetReservedID("world")
	c.Assert(i, Equals, NumericIdentity(2))
	c.Assert(i.String(), Equals, "world")

	// This is an obsoleted identity, we verify that it returns 0
	i = GetReservedID("cluster")
	c.Assert(i, Equals, NumericIdentity(0))
	c.Assert(i.String(), Equals, "unknown")

	i = GetReservedID("health")
	c.Assert(i, Equals, NumericIdentity(4))
	c.Assert(i.String(), Equals, "health")

	i = GetReservedID("init")
	c.Assert(i, Equals, NumericIdentity(5))
	c.Assert(i.String(), Equals, "init")

	i = GetReservedID("unmanaged")
	c.Assert(i, Equals, NumericIdentity(3))
	c.Assert(i.String(), Equals, "unmanaged")

	i = GetReservedID("kube-apiserver")
	c.Assert(i, Equals, NumericIdentity(7))
	c.Assert(i.String(), Equals, "kube-apiserver")

	c.Assert(GetReservedID("unknown"), Equals, IdentityUnknown)
	unknown := NumericIdentity(700)
	c.Assert(unknown.String(), Equals, "700")
}

func (s *IdentityTestSuite) TestIsReservedIdentity(c *C) {
	c.Assert(ReservedIdentityKubeAPIServer.IsReservedIdentity(), Equals, true)
	c.Assert(ReservedIdentityHealth.IsReservedIdentity(), Equals, true)
	c.Assert(ReservedIdentityHost.IsReservedIdentity(), Equals, true)
	c.Assert(ReservedIdentityWorld.IsReservedIdentity(), Equals, true)
	c.Assert(ReservedIdentityInit.IsReservedIdentity(), Equals, true)
	c.Assert(ReservedIdentityUnmanaged.IsReservedIdentity(), Equals, true)

	c.Assert(NumericIdentity(123456).IsReservedIdentity(), Equals, false)
}

func (s *IdentityTestSuite) TestRequiresGlobalIdentity(c *C) {
	prefix := netip.MustParsePrefix("0.0.0.0/0")
	c.Assert(RequiresGlobalIdentity(cidr.GetCIDRLabels(prefix)), Equals, false)

	prefix = netip.MustParsePrefix("192.168.23.0/24")
	c.Assert(RequiresGlobalIdentity(cidr.GetCIDRLabels(prefix)), Equals, false)

	c.Assert(RequiresGlobalIdentity(labels.NewLabelsFromModel([]string{"k8s:foo=bar"})), Equals, true)
}

func (s *IdentityTestSuite) TestNewIdentityFromLabelArray(c *C) {
	id := NewIdentityFromLabelArray(NumericIdentity(1001),
		labels.NewLabelArrayFromSortedList("unspec:a=;unspec:b;unspec:c=d"))

	lbls := labels.Labels{
		"a": labels.ParseLabel("a"),
		"c": labels.ParseLabel("c=d"),
		"b": labels.ParseLabel("b"),
	}
	c.Assert(id.ID, Equals, NumericIdentity(1001))
	c.Assert(id.Labels, checker.DeepEquals, lbls)
	c.Assert(id.LabelArray, checker.DeepEquals, lbls.LabelArray())
}

func TestLookupReservedIdentityByLabels(t *testing.T) {
	type want struct {
		id     NumericIdentity
		labels labels.Labels
	}
	tests := []struct {
		name string
		args labels.Labels
		want *want
	}{
		{
			name: "nil",
			args: nil,
			want: nil,
		},
		{
			name: "host",
			args: labels.LabelHost,
			want: &want{
				id:     ReservedIdentityHost,
				labels: labels.LabelHost,
			},
		},
		{
			name: "non-reserved",
			args: labels.NewLabelsFromModel([]string{"foo"}),
			want: nil,
		},
		{
			name: "non-reserved-2",
			args: labels.NewLabelsFromModel([]string{"reserved:init", "foo"}),
			want: nil,
		},
		{
			name: "health",
			args: labels.LabelHealth,
			want: &want{
				id:     ReservedIdentityHealth,
				labels: labels.LabelHealth,
			},
		},
		{
			name: "remote-node",
			args: labels.LabelRemoteNode,
			want: &want{
				id:     ReservedIdentityRemoteNode,
				labels: labels.LabelRemoteNode,
			},
		},
		{
			name: "kube-apiserver",
			args: labels.Map2Labels(map[string]string{
				labels.LabelKubeAPIServer.String(): "",
				labels.LabelRemoteNode.String():    "",
			}, ""),
			want: &want{
				id: ReservedIdentityKubeAPIServer,
				labels: labels.Map2Labels(map[string]string{
					labels.LabelKubeAPIServer.String(): "",
					labels.LabelRemoteNode.String():    "",
				}, ""),
			},
		},
		{
			name: "kube-apiserver-and-host",
			args: labels.Map2Labels(map[string]string{
				labels.LabelKubeAPIServer.String(): "",
				labels.LabelHost.String():          "",
			}, ""),
			want: &want{ // Should always still be host reserved identity
				id: ReservedIdentityHost,
				labels: labels.Map2Labels(map[string]string{
					labels.LabelKubeAPIServer.String(): "",
					labels.LabelHost.String():          "",
				}, ""),
			},
		},
		{
			name: "host-and-kube-apiserver",
			args: labels.Map2Labels(map[string]string{
				labels.LabelHost.String():          "",
				labels.LabelKubeAPIServer.String(): "",
			}, ""),
			want: &want{ // Should always still be host reserved identity
				id: ReservedIdentityHost,
				labels: labels.Map2Labels(map[string]string{
					labels.LabelHost.String():          "",
					labels.LabelKubeAPIServer.String(): "",
				}, ""),
			},
		},
		{
			name: "kube-apiserver-and-remote-node",
			args: labels.Map2Labels(map[string]string{
				labels.LabelKubeAPIServer.String(): "",
				labels.LabelRemoteNode.String():    "",
			}, ""),
			want: &want{
				id: ReservedIdentityKubeAPIServer,
				labels: labels.Map2Labels(map[string]string{
					labels.LabelKubeAPIServer.String(): "",
					labels.LabelRemoteNode.String():    "",
				}, ""),
			},
		},
		{
			name: "remote-node-and-kube-apiserver",
			args: labels.Map2Labels(map[string]string{
				labels.LabelRemoteNode.String():    "",
				labels.LabelKubeAPIServer.String(): "",
			}, ""),
			want: &want{
				id: ReservedIdentityKubeAPIServer,
				labels: labels.Map2Labels(map[string]string{
					labels.LabelRemoteNode.String():    "",
					labels.LabelKubeAPIServer.String(): "",
				}, ""),
			},
		},
		{
			name: "ingress",
			args: labels.LabelIngress,
			want: &want{
				id:     ReservedIdentityIngress,
				labels: labels.LabelIngress,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := LookupReservedIdentityByLabels(tt.args)
			if tt.want == nil {
				assert.Nil(t, id)
				return
			}
			assert.NotNil(t, id)
			assert.Equal(t, tt.want.id, id.ID)
			assert.Equal(t, tt.want.labels, id.Labels)
		})
	}
}

func TestIPIdentityPair_PrefixString(t *testing.T) {
	ipv6Mask := make(net.IPMask, net.IPv6len)
	for i := range ipv6Mask {
		ipv6Mask[i] = 255
	}

	tests := []struct {
		name     string
		expected string
		pair     *IPIdentityPair
	}{
		{
			name:     "IPv4 with mask",
			expected: "10.1.128.15/32",
			pair: &IPIdentityPair{
				IP:           net.ParseIP("10.1.128.15"),
				Mask:         net.IPv4Mask(255, 255, 255, 255),
				HostIP:       net.ParseIP("10.1.128.15"),
				ID:           1,
				Key:          3,
				Metadata:     "metadata",
				K8sNamespace: "kube-system",
				K8sPodName:   "pod-name",
				NamedPorts: []NamedPort{
					{Name: "port", Port: 8080, Protocol: "TCP"},
				},
			},
		},
		{
			name:     "IPv4 without mask",
			expected: "10.1.128.15",
			pair: &IPIdentityPair{
				IP:           net.ParseIP("10.1.128.15"),
				HostIP:       net.ParseIP("10.1.128.15"),
				ID:           1,
				Key:          3,
				Metadata:     "metadata",
				K8sNamespace: "kube-system",
				K8sPodName:   "pod-name",
				NamedPorts: []NamedPort{
					{Name: "port", Port: 8080, Protocol: "TCP"},
				},
			},
		},
		{
			name:     "IPv4 encoded as IPv6 with mask",
			expected: "10.1.128.15/128",
			pair: &IPIdentityPair{
				IP:           net.ParseIP("::ffff:a01:800f"),
				Mask:         ipv6Mask,
				HostIP:       net.ParseIP("::ffff:a01:800f"),
				ID:           1,
				Key:          3,
				Metadata:     "metadata",
				K8sNamespace: "kube-system",
				K8sPodName:   "pod-name",
				NamedPorts: []NamedPort{
					{Name: "port", Port: 8080, Protocol: "TCP"},
				},
			},
		},
		{
			name:     "IPv4 encoded as IPv6 without mask",
			expected: "10.1.128.15",
			pair: &IPIdentityPair{
				IP:           net.ParseIP("::ffff:a01:800f"),
				HostIP:       net.ParseIP("::ffff:a01:800f"),
				ID:           1,
				Key:          3,
				Metadata:     "metadata",
				K8sNamespace: "kube-system",
				K8sPodName:   "pod-name",
				NamedPorts: []NamedPort{
					{Name: "port", Port: 8080, Protocol: "TCP"},
				},
			},
		},
		{
			name:     "IPv6 local with mask",
			expected: "fd12:3456:789a:1::1/128",
			pair: &IPIdentityPair{
				IP:           net.ParseIP("fd12:3456:789a:1::1"),
				Mask:         ipv6Mask,
				HostIP:       net.ParseIP("fd12:3456:789a:1::1"),
				ID:           1,
				Key:          3,
				Metadata:     "metadata",
				K8sNamespace: "kube-system",
				K8sPodName:   "pod-name",
				NamedPorts: []NamedPort{
					{Name: "port", Port: 8080, Protocol: "TCP"},
				},
			},
		},
		{
			name:     "IPv6 local without mask",
			expected: "fd12:3456:789a:1::1",
			pair: &IPIdentityPair{
				IP:           net.ParseIP("fd12:3456:789a:1::1"),
				HostIP:       net.ParseIP("fd12:3456:789a:1::1"),
				ID:           1,
				Key:          3,
				Metadata:     "metadata",
				K8sNamespace: "kube-system",
				K8sPodName:   "pod-name",
				NamedPorts: []NamedPort{
					{Name: "port", Port: 8080, Protocol: "TCP"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix := tt.pair.PrefixString()
			assert.Equal(t, len(tt.expected), len(prefix))
			assert.Equal(t, tt.expected, prefix)
		})
	}
}

func BenchmarkIPIdentityPair_PrefixString(b *testing.B) {
	cases := []struct {
		name     string
		expected string
		pair     *IPIdentityPair
	}{
		{
			name:     "host",
			expected: "10.1.128.15/32",
			pair: &IPIdentityPair{
				IP:           net.ParseIP("10.1.128.15"),
				Mask:         net.IPv4Mask(255, 255, 255, 255),
				HostIP:       net.ParseIP("10.1.128.15"),
				ID:           1,
				Key:          3,
				Metadata:     "metadata",
				K8sNamespace: "kube-system",
				K8sPodName:   "pod-name",
				NamedPorts: []NamedPort{
					{Name: "port", Port: 8080, Protocol: "TCP"},
				},
			},
		},
		{
			name: "not host",
			pair: &IPIdentityPair{
				IP:           net.ParseIP("10.1.128.15"),
				HostIP:       net.ParseIP("10.1.128.15"),
				ID:           1,
				Key:          3,
				Metadata:     "metadata",
				K8sNamespace: "kube-system",
				K8sPodName:   "pod-name",
				NamedPorts: []NamedPort{
					{Name: "port", Port: 8080, Protocol: "TCP"},
				},
			},
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for _, tt := range cases {
		b.Run(tt.name, func(bb *testing.B) {
			for i := 0; i < bb.N; i++ {
				_ = tt.pair.PrefixString()
			}
		})
	}
}
