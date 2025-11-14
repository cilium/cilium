// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policychecks

import (
	"context"
	"log/slog"
	"reflect"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

type BackendTLSPolicyInput struct {
	Ctx              context.Context
	Logger           *slog.Logger
	Client           client.Client
	BackendTLSPolicy *gatewayv1.BackendTLSPolicy
}

func (b *BackendTLSPolicyInput) GetNamespace() string {
	return b.BackendTLSPolicy.GetNamespace()
}

func (b *BackendTLSPolicyInput) GetGVK() schema.GroupVersionKind {
	return gatewayv1.SchemeGroupVersion.WithKind("HTTPRoute")
}

func (b *BackendTLSPolicyInput) GetClient() client.Client {
	return b.Client
}

func (b *BackendTLSPolicyInput) GetContext() context.Context {
	return b.Ctx
}

func (b *BackendTLSPolicyInput) Log() *slog.Logger {
	return b.Logger
}

func (b *BackendTLSPolicyInput) GetTargetRefs() []gatewayv1.LocalPolicyTargetReferenceWithSectionName {
	return b.BackendTLSPolicy.Spec.TargetRefs
}

func (b *BackendTLSPolicyInput) SetAncestorCondition(parentRef gatewayv1.ParentReference, condition metav1.Condition) {
	// fill in the condition
	condition.LastTransitionTime = metav1.NewTime(time.Now())
	condition.ObservedGeneration = b.BackendTLSPolicy.GetGeneration()

	index := -1
	for i, ancestor := range b.BackendTLSPolicy.Status.Ancestors {
		if reflect.DeepEqual(ancestor.AncestorRef, parentRef) {
			index = i
			break
		}
	}

	if index != -1 {
		b.BackendTLSPolicy.Status.Ancestors[index].Conditions = helpers.MergeConditions(b.BackendTLSPolicy.Status.Ancestors[index].Conditions, condition)
		return
	}

	b.BackendTLSPolicy.Status.Ancestors = append(b.BackendTLSPolicy.Status.Ancestors, gatewayv1.PolicyAncestorStatus{
		AncestorRef:    parentRef,
		ControllerName: gatewayv1.GatewayController(controllerName),
		Conditions: []metav1.Condition{
			condition,
		},
	})
}
