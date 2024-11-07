// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func Test_getService(t *testing.T) {
	resource := model.FullyQualifiedResource{
		Name:      "dummy-ingress",
		Namespace: "dummy-namespace",
		Version:   "v1",
		Kind:      "Ingress",
		UID:       "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
	}

	t.Run("Default LB service", func(t *testing.T) {
		it := &dedicatedIngressTranslator{}
		res := it.getService(resource, nil, false)
		require.Equal(t, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cilium-ingress-dummy-ingress",
				Namespace: "dummy-namespace",
				Labels:    map[string]string{"cilium.io/ingress": "true"},
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "networking.k8s.io/v1",
						Kind:       "Ingress",
						Name:       "dummy-ingress",
						UID:        "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
						Controller: ptr.To(true),
					},
				},
			},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeLoadBalancer,
				Ports: []corev1.ServicePort{
					{
						Name:     "http",
						Protocol: "TCP",
						Port:     80,
					},
					{
						Name:     "https",
						Protocol: "TCP",
						Port:     443,
					},
				},
			},
		}, res)
	})

	t.Run("Default LB service with TLS only", func(t *testing.T) {
		it := &dedicatedIngressTranslator{}
		res := it.getService(resource, nil, true)
		require.Equal(t, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cilium-ingress-dummy-ingress",
				Namespace: "dummy-namespace",
				Labels:    map[string]string{"cilium.io/ingress": "true"},
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "networking.k8s.io/v1",
						Kind:       "Ingress",
						Name:       "dummy-ingress",
						UID:        "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
						Controller: ptr.To(true),
					},
				},
			},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeLoadBalancer,
				Ports: []corev1.ServicePort{
					{
						Name:     "https",
						Protocol: "TCP",
						Port:     443,
					},
				},
			},
		}, res)
	})

	t.Run("Invalid LB service annotation, defaults to LoadBalancer", func(t *testing.T) {
		it := &dedicatedIngressTranslator{}
		res := it.getService(resource, &model.Service{
			Type: "InvalidServiceType",
		}, false)
		require.Equal(t, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cilium-ingress-dummy-ingress",
				Namespace: "dummy-namespace",
				Labels:    map[string]string{"cilium.io/ingress": "true"},
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "networking.k8s.io/v1",
						Kind:       "Ingress",
						Name:       "dummy-ingress",
						UID:        "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
						Controller: ptr.To(true),
					},
				},
			},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeLoadBalancer,
				Ports: []corev1.ServicePort{
					{
						Name:     "http",
						Protocol: "TCP",
						Port:     80,
					},
					{
						Name:     "https",
						Protocol: "TCP",
						Port:     443,
					},
				},
			},
		}, res)
	})

	t.Run("Node Port service", func(t *testing.T) {
		var insecureNodePort uint32 = 3000
		var secureNodePort uint32 = 3001
		it := &dedicatedIngressTranslator{}
		res := it.getService(resource, &model.Service{
			Type:             "NodePort",
			InsecureNodePort: &insecureNodePort,
			SecureNodePort:   &secureNodePort,
		}, false)
		require.Equal(t, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cilium-ingress-dummy-ingress",
				Namespace: "dummy-namespace",
				Labels:    map[string]string{"cilium.io/ingress": "true"},
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "networking.k8s.io/v1",
						Kind:       "Ingress",
						Name:       "dummy-ingress",
						UID:        "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
						Controller: ptr.To(true),
					},
				},
			},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeNodePort,
				Ports: []corev1.ServicePort{
					{
						Name:     "http",
						Protocol: "TCP",
						Port:     80,
						NodePort: 3000,
					},
					{
						Name:     "https",
						Protocol: "TCP",
						Port:     443,
						NodePort: 3001,
					},
				},
			},
		}, res)
	})
}

func Test_getEndpointForIngress(t *testing.T) {
	res := getEndpoints(model.FullyQualifiedResource{
		Name:      "dummy-ingress",
		Namespace: "dummy-namespace",
		Version:   "v1",
		Kind:      "Ingress",
		UID:       "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
	})

	require.Equal(t, &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cilium-ingress-dummy-ingress",
			Namespace: "dummy-namespace",
			Labels:    map[string]string{"cilium.io/ingress": "true"},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "networking.k8s.io/v1",
					Kind:       "Ingress",
					Name:       "dummy-ingress",
					UID:        "d4bd3dc3-2ac5-4ab4-9dca-89c62c60177e",
					Controller: ptr.To(true),
				},
			},
		},
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: []corev1.EndpointAddress{{IP: "192.192.192.192"}},
				Ports:     []corev1.EndpointPort{{Port: 9999}},
			},
		},
	}, res)
}

func Test_translator_Translate(t *testing.T) {
	type args struct {
		m                            *model.Model
		useProxyProtocol             bool
		hostNetworkEnabled           bool
		hostNetworkNodeLabelSelector *slim_metav1.LabelSelector
		ipv4Enabled                  bool
		ipv6Enabled                  bool
	}
	tests := []struct {
		name          string
		args          args
		want          *ciliumv2.CiliumEnvoyConfig
		wantLBSvcType corev1.ServiceType
		wantErr       bool
	}{
		{
			name: "Conformance/DefaultBackend",
			args: args{
				m: &model.Model{
					HTTP: defaultBackendListeners,
				},
			},
			want:          defaultBackendListenersCiliumEnvoyConfig,
			wantLBSvcType: corev1.ServiceTypeLoadBalancer,
		},
		{
			name: "Conformance/HostRules",
			args: args{
				m: &model.Model{
					HTTP: hostRulesListenersEnforceHTTPS,
				},
			},
			want:          hostRulesListenersEnforceHTTPSCiliumEnvoyConfig,
			wantLBSvcType: corev1.ServiceTypeLoadBalancer,
		},
		{
			name: "Conformance/HostRules,no Force HTTPS",
			args: args{
				m: &model.Model{
					HTTP: hostRulesListeners,
				},
			},
			want:          hostRulesListenersCiliumEnvoyConfig,
			wantLBSvcType: corev1.ServiceTypeLoadBalancer,
		},
		{
			name: "Conformance/PathRules",
			args: args{
				m: &model.Model{
					HTTP: pathRulesListeners,
				},
			},
			want:          pathRulesListenersCiliumEnvoyConfig,
			wantLBSvcType: corev1.ServiceTypeLoadBalancer,
		},
		{
			name: "Conformance/ProxyProtocol",
			args: args{
				m: &model.Model{
					HTTP: proxyProtocolListeners,
				},
				useProxyProtocol: true,
			},
			want:          proxyProtoListenersCiliumEnvoyConfig,
			wantLBSvcType: corev1.ServiceTypeLoadBalancer,
		},
		{
			name: "Conformance/HostNetwork",
			args: args{
				m: &model.Model{
					HTTP: hostNetworkListeners(55555),
				},
				hostNetworkEnabled:           true,
				hostNetworkNodeLabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]slim_metav1.MatchLabelsValue{"a": "b"}},
				ipv4Enabled:                  true,
			},
			want:          hostNetworkListenersCiliumEnvoyConfig("0.0.0.0", 55555, &slim_metav1.LabelSelector{MatchLabels: map[string]slim_metav1.MatchLabelsValue{"a": "b"}}),
			wantLBSvcType: corev1.ServiceTypeClusterIP,
		},
		{
			name: "ComplexNodePortIngress",
			args: args{
				m: &model.Model{
					HTTP: complexNodePortIngressListeners,
				},
				hostNetworkEnabled:           true,
				hostNetworkNodeLabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]slim_metav1.MatchLabelsValue{"a": "b"}},
				ipv4Enabled:                  true,
			},
			want:          complexNodePortIngressCiliumEnvoyConfig,
			wantLBSvcType: corev1.ServiceTypeNodePort,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trans := &dedicatedIngressTranslator{
				cecTranslator:      translation.NewCECTranslator("cilium-secrets", tt.args.useProxyProtocol, false, false, 60, tt.args.hostNetworkEnabled, tt.args.hostNetworkNodeLabelSelector, tt.args.ipv4Enabled, tt.args.ipv6Enabled, 0),
				hostNetworkEnabled: tt.args.hostNetworkEnabled,
			}

			cec, svc, ep, err := trans.Translate(tt.args.m)
			require.Equal(t, tt.wantErr, err != nil, "Error mismatch")

			diffOutput := cmp.Diff(tt.want, cec, protocmp.Transform())
			if len(diffOutput) != 0 {
				t.Errorf("CiliumEnvoyConfigs did not match:\n%s\n", diffOutput)
			}

			require.NotNil(t, svc)
			assert.Equal(t, tt.wantLBSvcType, svc.Spec.Type)

			require.NotNil(t, ep)
		})
	}
}
