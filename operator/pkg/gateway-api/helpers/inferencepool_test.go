// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	gateway_inf_ext "sigs.k8s.io/gateway-api-inference-extension/api/v1"
)

func TestShadowServiceName(t *testing.T) {
	require.Equal(t, "llm-pool-shadow-service", ShadowServiceName("llm-pool"))
	require.Equal(t, ShadowServicePostfix, ShadowServiceName(""))
}

func TestHasInferencePoolSupport(t *testing.T) {
	t.Run("registered", func(t *testing.T) {
		scheme := TestScheme([]schema.GroupVersionKind{GatewayIEV1GVK(InferencePoolKind)})
		require.True(t, HasInferencePoolSupport(scheme))
	})

	t.Run("not registered", func(t *testing.T) {
		scheme := TestScheme(nil)
		require.False(t, HasInferencePoolSupport(scheme))
	})
}

func TestDesiredShadowService(t *testing.T) {
	infPool := &gateway_inf_ext.InferencePool{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "llm-pool",
			Namespace: "default",
			UID:       apitypes.UID("pool-uid"),
		},
		Spec: gateway_inf_ext.InferencePoolSpec{
			Selector: gateway_inf_ext.LabelSelector{
				MatchLabels: map[gateway_inf_ext.LabelKey]gateway_inf_ext.LabelValue{
					"app": "llm-server",
				},
			},
			TargetPorts: []gateway_inf_ext.Port{
				{Number: 8000},
			},
		},
	}

	svc := DesiredShadowService(infPool)

	require.Equal(t, "llm-pool-shadow-service", svc.Name)
	require.Equal(t, "default", svc.Namespace)
	require.Equal(t, corev1.ServiceTypeClusterIP, svc.Spec.Type)
	require.Equal(t, "None", svc.Spec.ClusterIP)
	require.Equal(t, map[string]string{"app": "llm-server"}, svc.Spec.Selector)
	require.Equal(t, []corev1.ServicePort{{
		Name:       "port-8000",
		Port:       8000,
		Protocol:   corev1.ProtocolTCP,
		TargetPort: intstr.FromInt(8000),
	}}, svc.Spec.Ports)

	require.Len(t, svc.OwnerReferences, 1)
	owner := svc.OwnerReferences[0]
	require.Equal(t, gateway_inf_ext.GroupVersion.String(), owner.APIVersion)
	require.Equal(t, "InferencePool", owner.Kind)
	require.Equal(t, "llm-pool", owner.Name)
	require.Equal(t, apitypes.UID("pool-uid"), owner.UID)
	require.NotNil(t, owner.Controller)
	require.True(t, *owner.Controller)
}

func TestGetInferencePoolPorts(t *testing.T) {
	tests := []struct {
		name  string
		ports []gateway_inf_ext.Port
		want  []corev1.ServicePort
	}{
		{
			name:  "no ports",
			ports: nil,
			want:  []corev1.ServicePort{},
		},
		{
			name:  "single port",
			ports: []gateway_inf_ext.Port{{Number: 8000}},
			want: []corev1.ServicePort{{
				Name: "port-8000", Port: 8000, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt(8000),
			}},
		},
		{
			name:  "multiple ports",
			ports: []gateway_inf_ext.Port{{Number: 8000}, {Number: 9000}},
			want: []corev1.ServicePort{
				{Name: "port-8000", Port: 8000, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt(8000)},
				{Name: "port-9000", Port: 9000, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt(9000)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := &gateway_inf_ext.InferencePool{Spec: gateway_inf_ext.InferencePoolSpec{TargetPorts: tt.ports}}
			require.Equal(t, tt.want, getInferencePoolPorts(pool))
		})
	}
}

func TestGetInferencePoolSelector(t *testing.T) {
	tests := []struct {
		name        string
		matchLabels map[gateway_inf_ext.LabelKey]gateway_inf_ext.LabelValue
		want        map[string]string
	}{
		{
			name:        "no labels",
			matchLabels: nil,
			want:        map[string]string{},
		},
		{
			name:        "single label",
			matchLabels: map[gateway_inf_ext.LabelKey]gateway_inf_ext.LabelValue{"app": "llm-server"},
			want:        map[string]string{"app": "llm-server"},
		},
		{
			name: "multiple labels",
			matchLabels: map[gateway_inf_ext.LabelKey]gateway_inf_ext.LabelValue{
				"app": "llm-server", "variant": "gpu",
			},
			want: map[string]string{"app": "llm-server", "variant": "gpu"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := &gateway_inf_ext.InferencePool{
				Spec: gateway_inf_ext.InferencePoolSpec{
					Selector: gateway_inf_ext.LabelSelector{MatchLabels: tt.matchLabels},
				},
			}
			require.Equal(t, tt.want, getInferencePoolSelector(pool))
		})
	}
}
