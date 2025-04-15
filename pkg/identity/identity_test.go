// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identity

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
)

func TestReservedID(t *testing.T) {
	i := GetReservedID("host")
	require.Equal(t, NumericIdentity(1), i)
	require.Equal(t, "host", i.String())

	i = GetReservedID("world")
	require.Equal(t, NumericIdentity(2), i)
	require.Equal(t, "world", i.String())

	// This is an obsoleted identity, we verify that it returns 0
	i = GetReservedID("cluster")
	require.Equal(t, NumericIdentity(0), i)
	require.Equal(t, "unknown", i.String())

	i = GetReservedID("health")
	require.Equal(t, NumericIdentity(4), i)
	require.Equal(t, "health", i.String())

	i = GetReservedID("init")
	require.Equal(t, NumericIdentity(5), i)
	require.Equal(t, "init", i.String())

	i = GetReservedID("unmanaged")
	require.Equal(t, NumericIdentity(3), i)
	require.Equal(t, "unmanaged", i.String())

	i = GetReservedID("kube-apiserver")
	require.Equal(t, NumericIdentity(7), i)
	require.Equal(t, "kube-apiserver", i.String())

	require.Equal(t, IdentityUnknown, GetReservedID("unknown"))
	unknown := NumericIdentity(700)
	require.Equal(t, "700", unknown.String())
}

func TestIsReservedIdentity(t *testing.T) {
	require.True(t, ReservedIdentityKubeAPIServer.IsReservedIdentity())
	require.True(t, ReservedIdentityHealth.IsReservedIdentity())
	require.True(t, ReservedIdentityHost.IsReservedIdentity())
	require.True(t, ReservedIdentityWorld.IsReservedIdentity())
	require.True(t, ReservedIdentityInit.IsReservedIdentity())
	require.True(t, ReservedIdentityUnmanaged.IsReservedIdentity())

	require.False(t, NumericIdentity(123456).IsReservedIdentity())
}

func TestRequiresGlobalIdentity(t *testing.T) {
	prefix := netip.MustParsePrefix("0.0.0.0/0")
	require.False(t, RequiresGlobalIdentity(labels.GetCIDRLabels(prefix)))

	prefix = netip.MustParsePrefix("192.168.23.0/24")
	require.False(t, RequiresGlobalIdentity(labels.GetCIDRLabels(prefix)))

	require.True(t, RequiresGlobalIdentity(labels.NewLabelsFromModel([]string{"k8s:foo=bar"})))
}

func TestScopeForLabels(t *testing.T) {
	tests := []struct {
		lbls  labels.Labels
		scope NumericIdentity
	}{
		{
			lbls:  labels.GetCIDRLabels(netip.MustParsePrefix("0.0.0.0/0")),
			scope: IdentityScopeLocal,
		},
		{
			lbls:  labels.GetCIDRLabels(netip.MustParsePrefix("192.168.23.0/24")),
			scope: IdentityScopeLocal,
		},
		{
			lbls:  labels.NewLabelsFromModel([]string{"k8s:foo=bar"}),
			scope: IdentityScopeGlobal,
		},
		{
			lbls:  labels.NewLabelsFromModel([]string{"reserved:world"}),
			scope: IdentityScopeGlobal,
		},
		{
			lbls:  labels.NewLabelsFromModel([]string{"reserved:unmanaged"}),
			scope: IdentityScopeGlobal,
		},
		{
			lbls:  labels.NewLabelsFromModel([]string{"reserved:health"}),
			scope: IdentityScopeGlobal,
		},
		{
			lbls:  labels.NewLabelsFromModel([]string{"reserved:init"}),
			scope: IdentityScopeGlobal,
		},
		{
			lbls:  labels.NewLabelsFromModel([]string{"reserved:ingress"}),
			scope: IdentityScopeGlobal,
		},
		{
			lbls:  labels.NewLabelsFromModel([]string{"reserved:remote-node"}),
			scope: IdentityScopeRemoteNode,
		},
		{
			lbls:  labels.NewLabelsFromModel([]string{"reserved:remote-node", "reserved:kube-apiserver"}),
			scope: IdentityScopeRemoteNode,
		},
	}

	for i, test := range tests {
		// ScopeForLabels requires this to return nil
		id := LookupReservedIdentityByLabels(test.lbls)
		if id != nil {
			continue
		}
		scope := ScopeForLabels(test.lbls)
		require.Equal(t, test.scope, scope, "%d / labels %s", i, test.lbls.String())
	}
}

func TestNewIdentityFromLabelArray(t *testing.T) {
	id := NewIdentityFromLabelArray(NumericIdentity(1001),
		labels.NewLabelArrayFromSortedList("unspec:a=;unspec:b;unspec:c=d"))

	lbls := labels.Labels{
		"a": labels.ParseLabel("a"),
		"c": labels.ParseLabel("c=d"),
		"b": labels.ParseLabel("b"),
	}
	require.Equal(t, NumericIdentity(1001), id.ID)
	require.Equal(t, lbls, id.Labels)
	require.Equal(t, lbls.LabelArray(), id.LabelArray)
}

func TestLookupReservedIdentityByLabels(t *testing.T) {
	cidrPrefix := netip.MustParsePrefix("10.0.0.0/24")
	type want struct {
		id     NumericIdentity
		labels labels.Labels
	}
	tests := []struct {
		name           string
		args           labels.Labels
		want           *want
		nodeCIDRPolicy bool
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
			name: "world",
			args: labels.LabelWorld,
			want: &want{
				id:     ReservedIdentityWorld,
				labels: labels.LabelWorld,
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
		{
			name: "cidr",
			args: labels.Map2Labels(map[string]string{
				labels.LabelWorld.String():                "",
				labels.GetCIDRLabels(cidrPrefix).String(): "",
			}, ""),
			want: nil,
		},
		{
			name:           "remote-node-with-cidr-policy",
			args:           labels.LabelRemoteNode,
			nodeCIDRPolicy: true,
			want:           nil,
		},
		{
			name: "kube-apiserver-and-remote-node-cidr-policy",
			args: labels.Map2Labels(map[string]string{
				labels.LabelKubeAPIServer.String(): "",
				labels.LabelRemoteNode.String():    "",
			}, ""),
			nodeCIDRPolicy: true,
			want:           nil,
		},
		{
			name: "remote-node-and-kube-apiserver-cidr-policy",
			args: labels.Map2Labels(map[string]string{
				labels.LabelRemoteNode.String():    "",
				labels.LabelKubeAPIServer.String(): "",
			}, ""),
			nodeCIDRPolicy: true,
			want:           nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldVal := option.Config.PolicyCIDRMatchMode
			defer func() {
				option.Config.PolicyCIDRMatchMode = oldVal
			}()
			if tt.nodeCIDRPolicy {
				option.Config.PolicyCIDRMatchMode = []string{"nodes"}
			} else {
				option.Config.PolicyCIDRMatchMode = []string{}
			}
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
			assert.Len(t, prefix, len(tt.expected))
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
			for bb.Loop() {
				_ = tt.pair.PrefixString()
			}
		})
	}
}
