// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package routechecks

import (
	"context"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

const (
	// controllerName is the gateway controller name used in cilium.
	controllerName = "io.cilium/gateway-controller"
)

type GenericRule interface {
	GetBackendRefs() []gatewayv1.BackendRef
}

type Input interface {
	GetRules() []GenericRule
	GetNamespace() string
	GetClient() client.Client
	GetContext() context.Context
	GetGVK() schema.GroupVersionKind
	GetGrants() []gatewayv1beta1.ReferenceGrant
	GetGateway(parent gatewayv1.ParentReference) (*gatewayv1.Gateway, error)
	GetParentGammaService(parent gatewayv1.ParentReference) (*corev1.Service, error)
	GetHostnames() []gatewayv1.Hostname

	SetParentCondition(ref gatewayv1.ParentReference, condition metav1.Condition)
	Log() *slog.Logger
}

type (
	CheckWithParentFunc func(input Input, ref gatewayv1.ParentReference) (bool, error)
)
