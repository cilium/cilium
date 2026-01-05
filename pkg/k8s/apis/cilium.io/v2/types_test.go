// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"net"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestCiliumNodeInstanceID(t *testing.T) {
	require.Empty(t, (*CiliumNode)(nil).InstanceID())
	require.Empty(t, (&CiliumNode{}).InstanceID())
	require.Equal(t, "foo", (&CiliumNode{Spec: NodeSpec{InstanceID: "foo"}}).InstanceID())
	require.Equal(t, "foo", (&CiliumNode{Spec: NodeSpec{InstanceID: "foo", ENI: eniTypes.ENISpec{InstanceID: "bar"}}}).InstanceID())
	require.Equal(t, "bar", (&CiliumNode{Spec: NodeSpec{ENI: eniTypes.ENISpec{InstanceID: "bar"}}}).InstanceID())
}

func BenchmarkSpecEquals(b *testing.B) {
	r := &CiliumNetworkPolicy{
		Spec: &api.Rule{
			EndpointSelector: api.EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{
						"foo3": "bar3",
						"foo4": "bar4",
					},
					MatchExpressions: []slim_metav1.LabelSelectorRequirement{
						{
							Key:      "any.foo",
							Operator: "NotIn",
							Values:   []string{"default"},
						},
					},
				},
			},
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{
							{
								LabelSelector: &slim_metav1.LabelSelector{
									MatchLabels: map[string]string{
										"foo3": "bar3",
										"foo4": "bar4",
									},
									MatchExpressions: []slim_metav1.LabelSelectorRequirement{
										{
											Key:      "any.foo",
											Operator: "NotIn",
											Values:   []string{"default"},
										},
									},
								},
							},
						},
						FromCIDR:     nil,
						FromCIDRSet:  nil,
						FromEntities: nil,
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{
								Port:     "8080",
								Protocol: "TCP",
							},
						},
						TerminatingTLS: &api.TLSContext{
							Secret: &api.Secret{
								Namespace: "",
								Name:      "",
							},
							TrustedCA:   "",
							Certificate: "",
							PrivateKey:  "",
						},
						OriginatingTLS: &api.TLSContext{
							Secret: &api.Secret{
								Namespace: "",
								Name:      "",
							},
							TrustedCA:   "",
							Certificate: "",
							PrivateKey:  "",
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{
									Path:   "path",
									Method: "method",
									Host:   "host",
								},
							},
						},
					}},
				},
			},
		},
	}
	o := r.DeepCopy()
	if !r.DeepEqual(o) {
		b.Error("Both structures should be equal!")
	}
	b.Run("Reflected SpecEquals", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			reflect.DeepEqual(r.Spec, o.Spec)
			reflect.DeepEqual(r.Specs, o.Specs)
		}
	})
	b.Run("Generated SpecEquals", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			r.DeepEqual(o)
		}
	})
}

func TestGetIP(t *testing.T) {
	n := CiliumNode{
		Spec: NodeSpec{
			Addresses: []NodeAddress{
				{
					Type: addressing.NodeExternalIP,
					IP:   "192.0.2.3",
				},
			},
		},
	}
	ip := n.GetIP(false)
	// Return the only IP present
	require.NotNil(t, ip)
	require.True(t, ip.Equal(net.ParseIP("192.0.2.3")))

	n.Spec.Addresses = append(n.Spec.Addresses, NodeAddress{IP: "w.x.y.z", Type: addressing.NodeExternalIP})
	ip = n.GetIP(false)
	// Invalid external IPv4 address should return the existing external IPv4 address
	require.NotNil(t, ip)
	require.True(t, ip.Equal(net.ParseIP("192.0.2.3")))

	n.Spec.Addresses = append(n.Spec.Addresses, NodeAddress{IP: "198.51.100.2", Type: addressing.NodeInternalIP})
	ip = n.GetIP(false)
	// The next priority should be NodeInternalIP
	require.NotNil(t, ip)
	require.True(t, ip.Equal(net.ParseIP("198.51.100.2")))

	n.Spec.Addresses = append(n.Spec.Addresses, NodeAddress{IP: "2001:DB8::1", Type: addressing.NodeExternalIP})
	ip = n.GetIP(true)
	// The next priority should be NodeExternalIP and IPv6
	require.NotNil(t, ip)
	require.True(t, ip.Equal(net.ParseIP("2001:DB8::1")))

	n.Spec.Addresses = append(n.Spec.Addresses, NodeAddress{IP: "w.x.y.z", Type: addressing.NodeExternalIP})
	ip = n.GetIP(true)
	// Invalid external IPv6 address should return the existing external IPv6 address
	require.NotNil(t, ip)
	require.True(t, ip.Equal(net.ParseIP("2001:DB8::1")))

	n.Spec.Addresses = append(n.Spec.Addresses, NodeAddress{IP: "2001:DB8::2", Type: addressing.NodeInternalIP})
	ip = n.GetIP(true)
	// The next priority should be NodeInternalIP and IPv6
	require.NotNil(t, ip)
	require.True(t, ip.Equal(net.ParseIP("2001:DB8::2")))

	n.Spec.Addresses = append(n.Spec.Addresses, NodeAddress{IP: "198.51.100.2", Type: addressing.NodeInternalIP})
	ip = n.GetIP(false)
	// Should still return NodeInternalIP and IPv4
	require.NotNil(t, ip)
	require.True(t, ip.Equal(net.ParseIP("198.51.100.2")))

	n.Spec.Addresses = []NodeAddress{{IP: "w.x.y.z", Type: addressing.NodeExternalIP}}
	ip = n.GetIP(false)
	// Return a nil IP when no valid IPv4 addresses exist
	require.Nil(t, ip)
	ip = n.GetIP(true)
	// Return a nil IP when no valid IPv6 addresses exist
	require.Nil(t, ip)
}
