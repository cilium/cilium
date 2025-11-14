// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policychecks

import (
	"context"
	"log/slog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	// controllerName is the gateway controller name used in cilium.
	controllerName = "io.cilium/gateway-controller"
)

type Input interface {
	GetNamespace() string
	GetClient() client.Client
	GetContext() context.Context
	GetGVK() schema.GroupVersionKind

	GetTargetRefs() []gatewayv1.LocalPolicyTargetReferenceWithSectionName

	SetAncestorCondition(ref gatewayv1.ParentReference, condition metav1.Condition)
	Log() *slog.Logger

	// ValidateSpec validates the spec of the Policy.
	// Unlike Routes, because there's not really any defined structure for the spec
	// of Policy (aside from targetRefs), we have to allow the types to do their own
	// thing, and have this check implemented directly on the underlying type rather
	// than in a separate CheckFunc.
	ValidateSpec(ancestorRef gatewayv1.ParentReference) error
}

type (
	CheckWithParentFunc func(input Input, ancestorRef gatewayv1.ParentReference, target types.NamespacedName, sectionName gatewayv1.SectionName) (bool, error)
)
