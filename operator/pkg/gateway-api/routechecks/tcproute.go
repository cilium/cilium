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

// TCPRouteInput is used to implement the Input interface for TCPRoute.
type TCPRouteInput struct {
	Ctx      context.Context
	Logger   *slog.Logger
	Client   client.Client
	Grants   *gatewayv1beta1.ReferenceGrantList
	TCPRoute *gatewayv1alpha2.TCPRoute

	gateways map[gatewayv1.ParentReference]*gatewayv1.Gateway
}

func (t *TCPRouteInput) SetParentCondition(ref gatewayv1.ParentReference, condition metav1.Condition) {
	condition.LastTransitionTime = metav1.NewTime(time.Now())
	condition.ObservedGeneration = t.TCPRoute.GetGeneration()

	t.mergeStatusConditions(ref, []metav1.Condition{
		condition,
	})
}

func (t *TCPRouteInput) SetAllParentCondition(condition metav1.Condition) {
	// fill in the condition
	condition.LastTransitionTime = metav1.NewTime(time.Now())
	condition.ObservedGeneration = t.TCPRoute.GetGeneration()

	for _, parent := range t.TCPRoute.Spec.ParentRefs {
		t.mergeStatusConditions(parent, []metav1.Condition{
			condition,
		})
	}
}

func (t *TCPRouteInput) mergeStatusConditions(parentRef gatewayv1alpha2.ParentReference, updates []metav1.Condition) {
	index := -1
	for i, parent := range t.TCPRoute.Status.RouteStatus.Parents {
		if reflect.DeepEqual(parent.ParentRef, parentRef) {
			index = i
			break
		}
	}
	if index != -1 {
		t.TCPRoute.Status.RouteStatus.Parents[index].Conditions = merge(t.TCPRoute.Status.RouteStatus.Parents[index].Conditions, updates...)
		return
	}
	t.TCPRoute.Status.RouteStatus.Parents = append(t.TCPRoute.Status.RouteStatus.Parents, gatewayv1alpha2.RouteParentStatus{
		ParentRef:      parentRef,
		ControllerName: controllerName,
		Conditions:     updates,
	})
}

func (t *TCPRouteInput) GetGrants() []gatewayv1beta1.ReferenceGrant {
	return t.Grants.Items
}

func (t *TCPRouteInput) GetNamespace() string {
	return t.TCPRoute.GetNamespace()
}

func (t *TCPRouteInput) GetGVK() schema.GroupVersionKind {
	return gatewayv1alpha2.SchemeGroupVersion.WithKind("TCPRoute")
}

func (t *TCPRouteInput) GetRules() []GenericRule {
	var rules []GenericRule
	for _, rule := range t.TCPRoute.Spec.Rules {
		rules = append(rules, &TCPRouteRule{rule})
	}
	return rules
}

func (t *TCPRouteInput) GetClient() client.Client {
	return t.Client
}

func (t *TCPRouteInput) GetContext() context.Context {
	return t.Ctx
}

// TCPRouteRule is used to implement the GenericRule interface for TCPRoute.
type TCPRouteRule struct {
	Rule gatewayv1alpha2.TCPRouteRule
}

func (t *TCPRouteRule) GetBackendRefs() []gatewayv1.BackendRef {
	return t.Rule.BackendRefs
}

func (t *TCPRouteInput) GetHostnames() []gatewayv1.Hostname {
	return nil
}

func (t *TCPRouteInput) GetGateway(parent gatewayv1.ParentReference) (*gatewayv1.Gateway, error) {
	if t.gateways == nil {
		t.gateways = make(map[gatewayv1.ParentReference]*gatewayv1.Gateway)
	}

	if gw, exists := t.gateways[parent]; exists {
		return gw, nil
	}

	ns := helpers.NamespaceDerefOr(parent.Namespace, t.GetNamespace())
	gw := &gatewayv1.Gateway{}

	if err := t.Client.Get(t.Ctx, client.ObjectKey{Namespace: ns, Name: string(parent.Name)}, gw); err != nil {
		if !k8serrors.IsNotFound(err) {
			return nil, fmt.Errorf("error while getting gateway: %w", err)
		}

		return nil, fmt.Errorf("gateway %q does not exist: %w", parent.Name, err)
	}

	t.gateways[parent] = gw

	return gw, nil
}

func (t *TCPRouteInput) GetParentGammaService(parent gatewayv1.ParentReference) (*corev1.Service, error) {
	return nil, fmt.Errorf("GAMMA support is not implemented in this reconciler")
}

func (t *TCPRouteInput) Log() *slog.Logger {
	return t.Logger
}
