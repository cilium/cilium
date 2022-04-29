// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package ingress

import (
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Test_getEndpointForIngress(t *testing.T) {
	ingress := baseIngress.DeepCopy()

	res := getEndpointsForIngress(ingress)
	assert.Equal(t, "cilium-ingress-dummy-ingress", res.Name)
	assert.Equal(t, "dummy-namespace", res.Namespace)
	assert.Equal(t, []metav1.OwnerReference{
		{
			APIVersion: "networking.k8s.io/v1",
			Kind:       "Ingress",
			Name:       "dummy-ingress",
			UID:        "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
		},
	}, res.OwnerReferences)
	assert.Equal(t, map[string]string{ciliumIngressLabelKey: "true"}, res.Labels)
	assert.Equal(t, res.Subsets, []v1.EndpointSubset{
		{
			Addresses: []v1.EndpointAddress{{IP: "192.192.192.192"}},
			Ports: []v1.EndpointPort{
				{
					Port: 9999,
				},
			},
		},
	})
}
