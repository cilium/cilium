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
	kindConfigMap     = "ConfigMap"

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
		parent.Group != nil && (*parent.Group == corev1.GroupName || *parent.Group == "core")
}

func IsGammaServiceEqual(parent gatewayv1.ParentReference, gammaService *corev1.Service, objNamespace string) bool {
	// In some uses, gammaService can have no TypeMeta set,
	// so, hard-code the Group here.
	gammaServiceGroup := corev1.SchemeGroupVersion.Group
	parentNamespace := NamespaceDerefOr(parent.Namespace, objNamespace)

	// Broken out from one line to make testing easier.

	// Kind or Group are nil, can't be a Gamma Service
	if parent.Kind == nil || parent.Group == nil {
		return false
	}

	// In some uses, gammaService can have no TypeMeta set,
	// so, hard-code the Kind here.
	if string(*parent.Kind) != "Service" {
		return false
	}

	if string(*parent.Group) != gammaServiceGroup {
		return false
	}

	if string(parentNamespace) != gammaService.Namespace {
		return false
	}

	if string(parent.Name) != gammaService.Name {
		return false
	}

	return true
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

func IsConfigMap(certRef gatewayv1.LocalObjectReference) bool {
	return certRef.Kind == kindConfigMap && certRef.Group == corev1.GroupName
}

func IsServiceTargetRef(tr gatewayv1.LocalPolicyTargetReferenceWithSectionName) bool {
	return tr.Kind == kindService && tr.Group == corev1.GroupName
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
