// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/operator/pkg/model"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

func TestGL4CTranslator_Translate(t *testing.T) {
	t.Run("empty model", func(t *testing.T) {
		translator := NewGL4CTranslator()
		result, err := translator.Translate("default", "test", nil)
		assert.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("tcp and udp listeners", func(t *testing.T) {
		translator := NewGL4CTranslator()
		input := &model.Model{
			L4: []model.L4Listener{
				{
					Name:     "tcp",
					Port:     80,
					Protocol: model.L4ProtocolTCP,
					Sources: []model.FullyQualifiedResource{
						{
							Name: "gateway",
						},
					},
					Routes: []model.L4Route{
						{
							Backends: []model.Backend{
								{
									Name:   "svc-b",
									Port:   &model.BackendPort{Port: 8081},
									Weight: ptr.To(int32(10)),
								},
								{
									Name: "svc-a",
									Port: &model.BackendPort{Port: 8080},
								},
								{
									Name:   "svc-skip",
									Port:   &model.BackendPort{Port: 8082},
									Weight: ptr.To(int32(0)),
								},
								{
									Name: "svc-no-port",
								},
							},
						},
					},
				},
				{
					Name:     "udp",
					Port:     53,
					Protocol: model.L4ProtocolUDP,
					Sources: []model.FullyQualifiedResource{
						{
							Name: "gateway",
						},
					},
					Routes: []model.L4Route{
						{
							Backends: []model.Backend{
								{
									Name: "svc-dns",
									Port: &model.BackendPort{Port: 5353},
								},
							},
						},
					},
				},
			},
		}

		result, err := translator.Translate("default", "ignored", input)
		require.NoError(t, err)
		require.NotNil(t, result)

		expected := &ciliumv2alpha1.CiliumGatewayL4Config{
			ObjectMeta: metav1.ObjectMeta{
				Name:      gatewayL4ConfigName("gateway"),
				Namespace: "default",
			},
			Spec: ciliumv2alpha1.CiliumGatewayL4ConfigSpec{
				GatewayRef: ciliumv2alpha1.CiliumGatewayReference{
					Name:      "gateway",
					Namespace: "default",
				},
				Listeners: []ciliumv2alpha1.CiliumGatewayL4Listener{
					{
						Name:     "tcp",
						Protocol: ciliumv2alpha1.L4ProtocolTCP,
						Port:     80,
						Backends: []ciliumv2alpha1.CiliumGatewayL4Backend{
							{
								Name:      "svc-a",
								Namespace: "default",
								Port:      8080,
								Weight:    ptr.To(uint16(loadbalancer.DefaultBackendWeight)),
							},
							{
								Name:      "svc-b",
								Namespace: "default",
								Port:      8081,
								Weight:    ptr.To(uint16(10)),
							},
						},
					},
					{
						Name:     "udp",
						Protocol: ciliumv2alpha1.L4ProtocolUDP,
						Port:     53,
						Backends: []ciliumv2alpha1.CiliumGatewayL4Backend{
							{
								Name:      "svc-dns",
								Namespace: "default",
								Port:      5353,
								Weight:    ptr.To(uint16(loadbalancer.DefaultBackendWeight)),
							},
						},
					},
				},
			},
		}
		assert.Equal(t, expected, result)
	})
}
