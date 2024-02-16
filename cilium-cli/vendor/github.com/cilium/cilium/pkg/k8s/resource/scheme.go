// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	discoveryv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	discoveryv1beta1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1beta1"
	networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
)

var scheme = runtime.NewScheme()

var localSchemeBuilder = runtime.SchemeBuilder{
	corev1.AddToScheme,
	discoveryv1beta1.AddToScheme,
	discoveryv1.AddToScheme,
	networkingv1.AddToScheme,
	cilium_api_v2.AddToScheme,
	cilium_api_v2alpha1.AddToScheme,
}

var AddToScheme = localSchemeBuilder.AddToScheme

func init() {
	utilruntime.Must(AddToScheme(scheme))
}
