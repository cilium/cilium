// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gateway_inf_ext "sigs.k8s.io/gateway-api-inference-extension/api/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

type InferencePoolStatusManager struct {
	client         client.Client
	controllerName string
}

func NewInferencePoolStatusManager(client client.Client, controllerName string) *InferencePoolStatusManager {
	return &InferencePoolStatusManager{
		client:         client,
		controllerName: controllerName,
	}
}

// SetInferencePoolStatuses updates this Gateway's parent entry in the status of
// every InferencePool referenced by the Gateway's attached route
func (m *InferencePoolStatusManager) SetInferencePoolStatuses(
	ctx context.Context,
	scopedLog *slog.Logger,
	gatewayName types.NamespacedName,
	pools []gateway_inf_ext.InferencePool,
	httpRoutes []gatewayv1.HTTPRoute,
) error {
	parentRef := gateway_inf_ext.ParentReference{
		Group:     ptr.To[gateway_inf_ext.Group](gatewayv1.GroupName),
		Kind:      gateway_inf_ext.Kind("Gateway"),
		Namespace: gateway_inf_ext.Namespace(gatewayName.Namespace),
		Name:      gateway_inf_ext.ObjectName(gatewayName.Name),
	}

	for i := range pools {
		pool := &pools[i]

		var conditions []metav1.Condition

		if inferencePoolReferencedByRoutes(pool, httpRoutes) {
			accepted, resolvedRefs, err := m.computeConditions(ctx, pool)
			if err != nil {
				return err
			}
			conditions = []metav1.Condition{accepted, resolvedRefs}
		}
		if err := m.updateInferencePoolStatus(ctx, scopedLog, pool, parentRef, conditions); err != nil {
			return err
		}
	}
	return nil
}

func (m *InferencePoolStatusManager) updateInferencePoolStatus(
	ctx context.Context,
	scopedLog *slog.Logger,
	pool *gateway_inf_ext.InferencePool,
	parentRef gateway_inf_ext.ParentReference,
	conditions []metav1.Condition,
) error {
	updated := pool.DeepCopy()
	updated.Status.Parents = m.mergeParent(updated.Status.Parents, parentRef, conditions)

	if cmp.Equal(pool.Status, updated.Status, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	scopedLog.DebugContext(ctx, "Updating InferencePool status")
	return m.client.Status().Update(ctx, updated)
}

// mergeParent replaces this controller's ParentStatus entry for parentRef with merged
// conditions. A nil conditions slice removes the entry (pool no longer referenced by us).
func (m *InferencePoolStatusManager) mergeParent(existing []gateway_inf_ext.ParentStatus, parentRef gateway_inf_ext.ParentReference, conditions []metav1.Condition) []gateway_inf_ext.ParentStatus {
	out := make([]gateway_inf_ext.ParentStatus, 0, len(existing)+1)
	found := false
	for _, ps := range existing {
		if string(ps.ControllerName) == m.controllerName && parentRefEqual(ps.ParentRef, parentRef) {
			found = true
			if conditions == nil {
				continue // drop the stale entry we own
			}
			ps.Conditions = helpers.MergeConditions(ps.Conditions, conditions...)
		}
		out = append(out, ps)
	}
	if !found && conditions != nil {
		out = append(out, gateway_inf_ext.ParentStatus{
			ParentRef:      parentRef,
			ControllerName: gateway_inf_ext.ControllerName(m.controllerName),
			Conditions:     helpers.MergeConditions(nil, conditions...),
		})
	}
	return out
}

func parentRefEqual(a, b gateway_inf_ext.ParentReference) bool {
	return a.Name == b.Name && a.Namespace == b.Namespace && a.Kind == b.Kind
}

func inferencePoolReferencedByRoutes(pool *gateway_inf_ext.InferencePool, httpRoutes []gatewayv1.HTTPRoute) bool {
	for _, hr := range httpRoutes {
		for _, rule := range hr.Spec.Rules {
			for _, be := range rule.BackendRefs {
				if !helpers.IsInferencePool(be.BackendObjectReference) {
					continue
				}
				ns := helpers.NamespaceDerefOr(be.Namespace, hr.Namespace)
				if string(be.Name) == pool.Name && ns == pool.Namespace {
					return true
				}
			}
		}
	}
	return false
}

// computeConditions builds the Accepted and ResolvedRefs conditions for a referenced pool.
func (m *InferencePoolStatusManager) computeConditions(ctx context.Context, pool *gateway_inf_ext.InferencePool) (accepted, resolvedRefs metav1.Condition, err error) {
	gen := pool.Generation
	now := metav1.Now()

	accepted = metav1.Condition{
		Type:               string(gateway_inf_ext.InferencePoolConditionAccepted),
		Status:             metav1.ConditionTrue,
		Reason:             string(gateway_inf_ext.InferencePoolReasonAccepted),
		Message:            "InferencePool accepted by Gateway",
		ObservedGeneration: gen,
		LastTransitionTime: now,
	}
	resolvedRefs = metav1.Condition{
		Type:               string(gateway_inf_ext.InferencePoolConditionResolvedRefs),
		Status:             metav1.ConditionTrue,
		Reason:             string(gateway_inf_ext.InferencePoolReasonResolvedRefs),
		Message:            "Referenced Endpoint Picker is valid",
		ObservedGeneration: gen,
		LastTransitionTime: now,
	}

	ref := pool.Spec.EndpointPickerRef
	if ref == nil {
		accepted.Status = metav1.ConditionFalse
		accepted.Reason = string(gateway_inf_ext.InferencePoolReasonEndpointPickerRefMissing)
		accepted.Message = "spec.endpointPickerRef is required"
		resolvedRefs.Status = metav1.ConditionFalse
		resolvedRefs.Reason = string(gateway_inf_ext.InferencePoolReasonInvalidExtensionRef)
		resolvedRefs.Message = "spec.endpointPickerRef is not set"
		return accepted, resolvedRefs, nil
	}

	// Only Service-kind EPP references are supported.
	kind := "Service"
	if ref.Kind != "" {
		kind = string(ref.Kind)
	}
	if kind != "Service" {
		resolvedRefs.Status = metav1.ConditionFalse
		resolvedRefs.Reason = string(gateway_inf_ext.InferencePoolReasonInvalidExtensionRef)
		resolvedRefs.Message = fmt.Sprintf("unsupported endpointPickerRef kind %q", kind)
		return accepted, resolvedRefs, nil
	}

	// The EPP Service must exist in the pool's namespace.
	svc := &corev1.Service{}
	if getErr := m.client.Get(ctx, types.NamespacedName{Namespace: pool.Namespace, Name: string(ref.Name)}, svc); getErr != nil {
		if !k8serrors.IsNotFound(getErr) {
			return accepted, resolvedRefs, fmt.Errorf("failed to get Endpoint Picker Service: %w", getErr)
		}
		resolvedRefs.Status = metav1.ConditionFalse
		resolvedRefs.Reason = string(gateway_inf_ext.InferencePoolReasonInvalidExtensionRef)
		resolvedRefs.Message = fmt.Sprintf("Endpoint Picker Service %s/%s does not exist", pool.Namespace, ref.Name)
	}

	return accepted, resolvedRefs, nil
}
