// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"
)

const (
	kindGateway       = "Gateway"
	kindService       = "Service"
	kindServiceImport = "ServiceImport"
	kindSecret        = "Secret"

	GatewayClassKind      string = "gatewayclasses"
	GatewayKind           string = "gateways"
	HTTPRouteKind         string = "httproutes"
	GRPCRouteKind         string = "grpcroutes"
	ReferenceGrantKind    string = "referencegrants"
	TLSRouteKind          string = "tlsroutes"
	TLSRouteListKind      string = "tlsroutelists"
	ServiceImportKind     string = "serviceimports"
	ServiceImportListKind string = "serviceimportlists"
)

func IsGateway(parent gatewayv1.ParentReference) bool {
	return (parent.Kind == nil || *parent.Kind == kindGateway) && (parent.Group == nil || *parent.Group == gatewayv1.GroupName)
}

func IsGammaService(parent gatewayv1.ParentReference) bool {
	return parent.Kind != nil && *parent.Kind == kindService &&
		parent.Group != nil && *parent.Group == corev1.GroupName
}

func IsService(be gatewayv1.BackendObjectReference) bool {
	return (be.Kind == nil || *be.Kind == kindService) && (be.Group == nil || *be.Group == corev1.GroupName)
}

func IsServiceImport(be gatewayv1.BackendObjectReference) bool {
	return be.Kind != nil && *be.Kind == kindServiceImport && be.Group != nil && *be.Group == mcsapiv1alpha1.GroupName
}

func IsSecret(secret gatewayv1.SecretObjectReference) bool {
	return (secret.Kind == nil || *secret.Kind == kindSecret) && (secret.Group == nil || *secret.Group == corev1.GroupName)
}

// getConcreteObject returns an instance of a concrete object type based on the
// given GroupVersionKind.
func GetConcreteObject(schemaType schema.GroupVersionKind) runtime.Object {
	kind := schemaType.Kind

	switch kind {
	case TLSRouteKind:
		return &gatewayv1alpha2.TLSRoute{}
	case TLSRouteListKind:
		return &gatewayv1alpha2.TLSRouteList{}
	case ServiceImportKind:
		return &mcsapiv1alpha1.ServiceImport{}
	case ServiceImportListKind:
		return &mcsapiv1alpha1.ServiceImportList{}
	default:
		// panic is okay here because this is a progammer error
		panic(fmt.Sprintf("Tried to get a concrete type that is not implemented, %s", schemaType.Kind))
	}
}
