// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package routechecks

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

// TLSRouteInput is used to implement the Input interface for TLSRoute
type TLSRouteInput struct {
	Ctx            context.Context
	Logger         *slog.Logger
	Client         client.Client
	Grants         *gatewayv1.ReferenceGrantList
	TLSRoute       *gatewayv1.TLSRoute
	ControllerName string

	gateways map[gatewayv1.ParentReference]ListenerOwner
}

func (t *TLSRouteInput) SetParentCondition(ref gatewayv1.ParentReference, condition metav1.Condition) {
	// fill in the condition
	condition.LastTransitionTime = metav1.NewTime(time.Now())
	condition.ObservedGeneration = t.TLSRoute.GetGeneration()

	t.mergeStatusConditions(ref, []metav1.Condition{
		condition,
	})
}

func (t *TLSRouteInput) SetAllParentCondition(condition metav1.Condition) {
	// fill in the condition
	condition.LastTransitionTime = metav1.NewTime(time.Now())
	condition.ObservedGeneration = t.TLSRoute.GetGeneration()

	for _, parent := range t.TLSRoute.Spec.ParentRefs {
		t.mergeStatusConditions(parent, []metav1.Condition{
			condition,
		})
	}
}

func (t *TLSRouteInput) mergeStatusConditions(parentRef gatewayv1.ParentReference, updates []metav1.Condition) {
	index := -1
	for i, parent := range t.TLSRoute.Status.RouteStatus.Parents {
		if reflect.DeepEqual(parent.ParentRef, parentRef) {
			index = i
			break
		}
	}
	if index != -1 {
		t.TLSRoute.Status.RouteStatus.Parents[index].Conditions = helpers.MergeConditions(t.TLSRoute.Status.RouteStatus.Parents[index].Conditions, updates...)
		return
	}
	t.TLSRoute.Status.RouteStatus.Parents = append(t.TLSRoute.Status.RouteStatus.Parents, gatewayv1.RouteParentStatus{
		ParentRef:      parentRef,
		ControllerName: gatewayv1.GatewayController(t.ControllerName),
		Conditions:     updates,
	})
}

func (t *TLSRouteInput) GetGrants() []gatewayv1.ReferenceGrant {
	if t.Grants == nil {
		return nil
	}
	return t.Grants.Items
}

func (t *TLSRouteInput) GetNamespace() string {
	return t.TLSRoute.GetNamespace()
}

func (t *TLSRouteInput) GetGVK() schema.GroupVersionKind {
	return gatewayv1.SchemeGroupVersion.WithKind("TLSRoute")
}

func (t *TLSRouteInput) GetRules() []GenericRule {
	var rules []GenericRule
	for _, rule := range t.TLSRoute.Spec.Rules {
		rules = append(rules, &TLSRouteRule{rule})
	}
	return rules
}

func (t *TLSRouteInput) GetClient() client.Client {
	return t.Client
}

func (t *TLSRouteInput) GetContext() context.Context {
	return t.Ctx
}

// TLSRouteRule is used to implement the GenericRule interface for TLSRoute
type TLSRouteRule struct {
	Rule gatewayv1.TLSRouteRule
}

func (t *TLSRouteRule) GetBackendRefs() []gatewayv1.BackendRef {
	return t.Rule.BackendRefs
}

func (t *TLSRouteInput) GetHostnames() []gatewayv1.Hostname {
	return t.TLSRoute.Spec.Hostnames
}

func (t *TLSRouteInput) GetListenerOwner(parent gatewayv1.ParentReference) (ListenerOwner, error) {
	if t.gateways == nil {
		t.gateways = make(map[gatewayv1.ParentReference]ListenerOwner)
	}

	if owner, exists := t.gateways[parent]; exists {
		return owner, nil
	}

	owner, err := ResolveListenerOwner(t.Ctx, t.Client, parent, t.GetNamespace())
	if err != nil {
		return nil, err
	}

	t.gateways[parent] = owner

	return owner, nil
}

func (t *TLSRouteInput) GetParentGammaService(parent gatewayv1.ParentReference) (*corev1.Service, error) {
	return nil, fmt.Errorf("GAMMA support is not implemented in this reconciler")
}

func (t *TLSRouteInput) Log() *slog.Logger {
	return t.Logger
}

func (t *TLSRouteInput) GetValidProtocols() []gatewayv1.ProtocolType {
	return []gatewayv1.ProtocolType{gatewayv1.TLSProtocolType}
}
