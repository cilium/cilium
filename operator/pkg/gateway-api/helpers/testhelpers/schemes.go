// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testhelpers

import (
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// TestScheme returns a scheme containing the core test types, required Gateway
// API types, and the requested optional Gateway API types.
func TestScheme(
	optionalKinds []schema.GroupVersionKind,
	registerGatewayAPITypes func(*runtime.Scheme, []schema.GroupVersionKind) error,
) *runtime.Scheme {
	scheme := runtime.NewScheme()

	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(ciliumv2.AddToScheme(scheme))
	utilruntime.Must(ciliumv2alpha1.AddToScheme(scheme))
	utilruntime.Must(apiextensionsv1.AddToScheme(scheme))
	utilruntime.Must(registerGatewayAPITypes(scheme, optionalKinds))

	return scheme
}
