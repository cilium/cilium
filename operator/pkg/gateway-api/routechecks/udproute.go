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
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

// UDPRouteInput is used to implement the Input interface for UDPRoute.
type UDPRouteInput struct {
	Ctx      context.Context
	Logger   *slog.Logger
	Client   client.Client
	Grants   *gatewayv1beta1.ReferenceGrantList
	UDPRoute *gatewayv1alpha2.UDPRoute

	gateways map[gatewayv1.ParentReference]*gatewayv1.Gateway
}

func (u *UDPRouteInput) SetParentCondition(ref gatewayv1.ParentReference, condition metav1.Condition) {
	condition.LastTransitionTime = metav1.NewTime(time.Now())
	condition.ObservedGeneration = u.UDPRoute.GetGeneration()

	u.mergeStatusConditions(ref, []metav1.Condition{
		condition,
	})
}

func (u *UDPRouteInput) SetAllParentCondition(condition metav1.Condition) {
	// fill in the condition
	condition.LastTransitionTime = metav1.NewTime(time.Now())
	condition.ObservedGeneration = u.UDPRoute.GetGeneration()

	for _, parent := range u.UDPRoute.Spec.ParentRefs {
		u.mergeStatusConditions(parent, []metav1.Condition{
			condition,
		})
	}
}

func (u *UDPRouteInput) mergeStatusConditions(parentRef gatewayv1alpha2.ParentReference, updates []metav1.Condition) {
	index := -1
	for i, parent := range u.UDPRoute.Status.RouteStatus.Parents {
		if reflect.DeepEqual(parent.ParentRef, parentRef) {
			index = i
			break
		}
	}
	if index != -1 {
		u.UDPRoute.Status.RouteStatus.Parents[index].Conditions = merge(u.UDPRoute.Status.RouteStatus.Parents[index].Conditions, updates...)
		return
	}
	u.UDPRoute.Status.RouteStatus.Parents = append(u.UDPRoute.Status.RouteStatus.Parents, gatewayv1alpha2.RouteParentStatus{
		ParentRef:      parentRef,
		ControllerName: controllerName,
		Conditions:     updates,
	})
}

func (u *UDPRouteInput) GetGrants() []gatewayv1beta1.ReferenceGrant {
	return u.Grants.Items
}

func (u *UDPRouteInput) GetNamespace() string {
	return u.UDPRoute.GetNamespace()
}

func (u *UDPRouteInput) GetGVK() schema.GroupVersionKind {
	return gatewayv1alpha2.SchemeGroupVersion.WithKind("UDPRoute")
}

func (u *UDPRouteInput) GetRules() []GenericRule {
	var rules []GenericRule
	for _, rule := range u.UDPRoute.Spec.Rules {
		rules = append(rules, &UDPRouteRule{rule})
	}
	return rules
}

func (u *UDPRouteInput) GetClient() client.Client {
	return u.Client
}

func (u *UDPRouteInput) GetContext() context.Context {
	return u.Ctx
}

// UDPRouteRule is used to implement the GenericRule interface for UDPRoute.
type UDPRouteRule struct {
	Rule gatewayv1alpha2.UDPRouteRule
}

func (u *UDPRouteRule) GetBackendRefs() []gatewayv1.BackendRef {
	return u.Rule.BackendRefs
}

func (u *UDPRouteInput) GetHostnames() []gatewayv1.Hostname {
	return nil
}

func (u *UDPRouteInput) GetGateway(parent gatewayv1.ParentReference) (*gatewayv1.Gateway, error) {
	if u.gateways == nil {
		u.gateways = make(map[gatewayv1.ParentReference]*gatewayv1.Gateway)
	}

	if gw, exists := u.gateways[parent]; exists {
		return gw, nil
	}

	ns := helpers.NamespaceDerefOr(parent.Namespace, u.GetNamespace())
	gw := &gatewayv1.Gateway{}

	if err := u.Client.Get(u.Ctx, client.ObjectKey{Namespace: ns, Name: string(parent.Name)}, gw); err != nil {
		if !k8serrors.IsNotFound(err) {
			return nil, fmt.Errorf("error while getting gateway: %w", err)
		}

		return nil, fmt.Errorf("gateway %q does not exist: %w", parent.Name, err)
	}

	u.gateways[parent] = gw

	return gw, nil
}

func (u *UDPRouteInput) GetParentGammaService(parent gatewayv1.ParentReference) (*corev1.Service, error) {
	return nil, fmt.Errorf("GAMMA support is not implemented in this reconciler")
}

func (u *UDPRouteInput) Log() *slog.Logger {
	return u.Logger
}
