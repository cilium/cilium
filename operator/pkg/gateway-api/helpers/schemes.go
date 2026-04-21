// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"fmt"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	mcsapiv1beta1 "sigs.k8s.io/mcs-api/pkg/apis/v1beta1"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

var RequiredGVKs = []schema.GroupVersionKind{
	gatewayv1.SchemeGroupVersion.WithKind(GatewayClassKind),
	gatewayv1.SchemeGroupVersion.WithKind(GatewayKind),
	gatewayv1.SchemeGroupVersion.WithKind(HTTPRouteKind),
	gatewayv1.SchemeGroupVersion.WithKind(GRPCRouteKind),
	gatewayv1.SchemeGroupVersion.WithKind(ReferenceGrantKind),
}

var AllOptionalKinds = []schema.GroupVersionKind{
	gatewayv1.SchemeGroupVersion.WithKind(TLSRouteKind),
	mcsapiv1beta1.SchemeGroupVersion.WithKind(ServiceImportKind),
}

var NoMCSOptionalKinds = []schema.GroupVersionKind{
	gatewayv1.SchemeGroupVersion.WithKind(TLSRouteKind),
}

func TestScheme(installedGVKs []schema.GroupVersionKind) *runtime.Scheme {
	scheme := runtime.NewScheme()

	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(ciliumv2.AddToScheme(scheme))
	utilruntime.Must(ciliumv2alpha1.AddToScheme(scheme))
	utilruntime.Must(apiextensionsv1.AddToScheme(scheme))

	RegisterGatewayAPITypesToScheme(scheme, installedGVKs)

	return scheme
}

func RegisterGatewayAPITypesToScheme(scheme *runtime.Scheme, optionalKinds []schema.GroupVersionKind) error {
	// Autodetection of installed types means we have to add things to the scheme
	// ourselves for non-Standard GroupVersions, we can't use the generated
	// functions.

	addToSchema := make(map[fmt.Stringer]func(s *runtime.Scheme) error)

	// We can safely install the GA resources
	addToSchema[gatewayv1.GroupVersion] = gatewayv1.AddToScheme

	for _, optionalKind := range optionalKinds {
		// Note that we're using the full GVK as the map key here - this is fine
		// because the key is just a fmt.Stringer
		// We need to do this because there needs to be one entry
		//
		// Note that these calls are usually done using the package-level
		// AddToScheme, but we can't use that here because we want to only
		// enable things on a per-resource basis.
		addToSchema[optionalKind] = func(s *runtime.Scheme) error {
			s.AddKnownTypes(optionalKind.GroupVersion(), GetConcreteObject(optionalKind))
			// We also need to add the List version to the Schema
			listKind := optionalKind.Kind[:len(optionalKind.Kind)-1] + "lists"
			optionalKindList := schema.GroupVersionKind{
				Group:   optionalKind.Group,
				Version: optionalKind.Version,
				Kind:    listKind,
			}
			s.AddKnownTypes(optionalKind.GroupVersion(), GetConcreteObject(optionalKindList))
			metav1.AddToGroupVersion(s, optionalKind.GroupVersion())
			return nil
		}
	}

	for gv, f := range addToSchema {
		if err := f(scheme); err != nil {
			return fmt.Errorf("failed to add types from %s to scheme: %w", gv, err)
		}
	}

	return nil
}
