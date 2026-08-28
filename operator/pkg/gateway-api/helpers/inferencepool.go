// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	gateway_inf_ext "sigs.k8s.io/gateway-api-inference-extension/api/v1"
)

const (
	ShadowServicePostfix = "-shadow-service"
)

// HasInferencePoolSupport returns if the InferencePool CRD is supported.
// This checks if the Gateway API Inference Extension v1 InferencePool CRD is registered in the client scheme.
func HasInferencePoolSupport(scheme *runtime.Scheme) bool {
	return scheme.Recognizes(GatewayIEV1GVK("InferencePool"))
}

func ShadowServiceName(name string) string {

	return string(name) + ShadowServicePostfix
}

// DesiredShadowService returns the Service object for a given InferencePool
func DesiredShadowService(infPool *gateway_inf_ext.InferencePool) *corev1.Service {
	name := ShadowServiceName(infPool.Name)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: infPool.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: gateway_inf_ext.GroupVersion.String(),
					Kind:       "InferencePool",
					Name:       infPool.Name,
					UID:        types.UID(infPool.UID),
					Controller: ptr.To(true),
				},
			},
		},
		Spec: corev1.ServiceSpec{
			Ports:     getInferencePoolPorts(infPool),
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: "None",
			Selector:  getInferencePoolSelector(infPool),
		},
	}
	return svc
}

func getInferencePoolPorts(infPool *gateway_inf_ext.InferencePool) []corev1.ServicePort {
	svcPorts := []corev1.ServicePort{}

	for _, port := range infPool.Spec.TargetPorts {
		svcPorts = append(svcPorts, corev1.ServicePort{
			Name:       fmt.Sprintf("port-%d", port.Number),
			Port:       int32(port.Number),
			Protocol:   corev1.ProtocolTCP,
			TargetPort: intstr.FromInt(int(port.Number)),
		})
	}

	return svcPorts
}

func getInferencePoolSelector(infPool *gateway_inf_ext.InferencePool) map[string]string {
	selector := make(map[string]string, 0)
	for k, v := range infPool.Spec.Selector.MatchLabels {
		selector[string(k)] = string(v)
	}
	return selector
}
