// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package testutils

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/identity/key"
	capi_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	idbackend "github.com/cilium/cilium/pkg/k8s/identitybackend"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
)

func CreateCIDObj(id string, lbs map[string]string) *capi_v2.CiliumIdentity {
	secLbs := make(map[string]string)
	for k, v := range lbs {
		fmt.Printf("Adding label %s=%s\n", k, v)
		secLbs[k] = v
	}

	k := key.GetCIDKeyFromLabels(secLbs, labels.LabelSourceK8s)
	secLbs = k.GetAsMap()

	selectedLabels, _ := idbackend.SanitizeK8sLabels(secLbs)

	return &capi_v2.CiliumIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:   id,
			Labels: selectedLabels,
		},
		SecurityLabels: secLbs,
	}
}

func CreateCIDObjNs(id string, pod *slim_corev1.Pod, namespace *slim_corev1.Namespace) *capi_v2.CiliumIdentity {
	lbs := k8sUtils.SanitizePodLabels(pod.ObjectMeta.Labels, namespace, "", "")
	secLbs := key.GetCIDKeyFromLabels(lbs, labels.LabelSourceK8s).GetAsMap()
	selectedLabels, _ := idbackend.SanitizeK8sLabels(secLbs)

	return &capi_v2.CiliumIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:   id,
			Labels: selectedLabels,
		},
		SecurityLabels: secLbs,
	}
}

func CreatePodObj(name, namespace string, lbs, annotations map[string]string) *slim_corev1.Pod {
	return &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      lbs,
			Annotations: annotations,
		},
		Spec: slim_corev1.PodSpec{},
		Status: slim_corev1.PodStatus{
			HostIP: "10.0.0.0",
			PodIPs: []slim_corev1.PodIP{
				{IP: "172.0.0.1"},
				{IP: "2001:db8::1"},
			},
		},
	}
}

func CreateNSObj(name string, lbs map[string]string) *slim_corev1.Namespace {
	if lbs == nil {
		lbs = make(map[string]string)
	}

	lbs["kubernetes.io/metadata.name"] = name

	return &slim_corev1.Namespace{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:   name,
			Labels: lbs,
		},
	}
}
