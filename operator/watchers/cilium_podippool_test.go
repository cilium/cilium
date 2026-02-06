// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func TestConvertV2Alpha1ToV2(t *testing.T) {
	tests := []struct {
		name     string
		input    *cilium_v2alpha1.CiliumPodIPPool
		expected *cilium_v2.CiliumPodIPPool
	}{
		{
			name: "basic conversion with IPv4 only",
			input: &cilium_v2alpha1.CiliumPodIPPool{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-pool",
				},
				Spec: cilium_v2alpha1.IPPoolSpec{
					IPv4: &cilium_v2alpha1.IPv4PoolSpec{
						CIDRs:    []cilium_v2alpha1.PoolCIDR{"10.0.0.0/16", "10.1.0.0/16"},
						MaskSize: 24,
					},
				},
			},
			expected: &cilium_v2.CiliumPodIPPool{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "cilium.io/v2",
					Kind:       "CiliumPodIPPool",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-pool",
				},
				Spec: cilium_v2.IPPoolSpec{
					IPv4: &cilium_v2.IPv4PoolSpec{
						CIDRs:    []cilium_v2.PoolCIDR{{CIDR: "10.0.0.0/16"}, {CIDR: "10.1.0.0/16"}},
						MaskSize: 24,
					},
				},
			},
		},
		{
			name: "basic conversion with IPv6 only",
			input: &cilium_v2alpha1.CiliumPodIPPool{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-pool-v6",
				},
				Spec: cilium_v2alpha1.IPPoolSpec{
					IPv6: &cilium_v2alpha1.IPv6PoolSpec{
						CIDRs:    []cilium_v2alpha1.PoolCIDR{"fd00:100::/80"},
						MaskSize: 96,
					},
				},
			},
			expected: &cilium_v2.CiliumPodIPPool{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "cilium.io/v2",
					Kind:       "CiliumPodIPPool",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-pool-v6",
				},
				Spec: cilium_v2.IPPoolSpec{
					IPv6: &cilium_v2.IPv6PoolSpec{
						CIDRs:    []cilium_v2.PoolCIDR{{CIDR: "fd00:100::/80"}},
						MaskSize: 96,
					},
				},
			},
		},
		{
			name: "dual-stack conversion",
			input: &cilium_v2alpha1.CiliumPodIPPool{
				ObjectMeta: metav1.ObjectMeta{
					Name: "dual-stack-pool",
				},
				Spec: cilium_v2alpha1.IPPoolSpec{
					IPv4: &cilium_v2alpha1.IPv4PoolSpec{
						CIDRs:    []cilium_v2alpha1.PoolCIDR{"10.0.0.0/16"},
						MaskSize: 24,
					},
					IPv6: &cilium_v2alpha1.IPv6PoolSpec{
						CIDRs:    []cilium_v2alpha1.PoolCIDR{"fd00:100::/80"},
						MaskSize: 96,
					},
				},
			},
			expected: &cilium_v2.CiliumPodIPPool{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "cilium.io/v2",
					Kind:       "CiliumPodIPPool",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "dual-stack-pool",
				},
				Spec: cilium_v2.IPPoolSpec{
					IPv4: &cilium_v2.IPv4PoolSpec{
						CIDRs:    []cilium_v2.PoolCIDR{{CIDR: "10.0.0.0/16"}},
						MaskSize: 24,
					},
					IPv6: &cilium_v2.IPv6PoolSpec{
						CIDRs:    []cilium_v2.PoolCIDR{{CIDR: "fd00:100::/80"}},
						MaskSize: 96,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertV2Alpha1ToV2(tt.input)

			assert.Equal(t, tt.expected.TypeMeta, result.TypeMeta)
			assert.Equal(t, tt.expected.ObjectMeta.Name, result.ObjectMeta.Name)
			assert.Equal(t, tt.expected.Spec.PodSelector, result.Spec.PodSelector)
			assert.Equal(t, tt.expected.Spec.NamespaceSelector, result.Spec.NamespaceSelector)

			if tt.expected.Spec.IPv4 != nil {
				assert.NotNil(t, result.Spec.IPv4)
				assert.Equal(t, tt.expected.Spec.IPv4.CIDRs, result.Spec.IPv4.CIDRs)
				assert.Equal(t, tt.expected.Spec.IPv4.MaskSize, result.Spec.IPv4.MaskSize)
			} else {
				assert.Nil(t, result.Spec.IPv4)
			}

			if tt.expected.Spec.IPv6 != nil {
				assert.NotNil(t, result.Spec.IPv6)
				assert.Equal(t, tt.expected.Spec.IPv6.CIDRs, result.Spec.IPv6.CIDRs)
				assert.Equal(t, tt.expected.Spec.IPv6.MaskSize, result.Spec.IPv6.MaskSize)
			} else {
				assert.Nil(t, result.Spec.IPv6)
			}
		})
	}
}
