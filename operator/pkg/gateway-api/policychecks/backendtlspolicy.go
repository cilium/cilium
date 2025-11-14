// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policychecks

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// controllerName is the gateway controller name used in cilium.
	controllerName = "io.cilium/gateway-controller"
)

type BackendTLSPolicyInput struct {
	Client           client.Client
	BackendTLSPolicy *gatewayv1.BackendTLSPolicy
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

func (b *BackendTLSPolicyInput) ValidateSpec(ctx context.Context, scopedLog *slog.Logger, ancestorRef gatewayv1.ParentReference) (bool, error) {
	if len(b.BackendTLSPolicy.Spec.Validation.CACertificateRefs) > 0 {
		if b.BackendTLSPolicy.Spec.Validation.WellKnownCACertificates != nil {
			// Firstly, we check that both CACertificateRefs and WellKnownCACertificates are not set.
			// This should be prevented by CEL on the CRDs, but it's not impossible to bypass.
			b.setRejectedConditions(ancestorRef, "Cannot have both CACertificateRefs and wellKnownCACertificates set",
				string(gatewayv1.PolicyReasonInvalid), string(gatewayv1.PolicyReasonInvalid))
			return false, nil
		}
		// Secondly, we check that there is only one CACertificateRef. We will ignore any additional
		// ones, but we want to tell people about that.
		if len(b.BackendTLSPolicy.Spec.Validation.CACertificateRefs) > 1 {
			b.setRejectedConditions(ancestorRef, "Having more than one CA Certificate Ref is not supported",
				string(gatewayv1.PolicyReasonInvalid), string(gatewayv1.PolicyReasonInvalid))
			return false, nil
		}
		// Thirdly, check that the CACertificateRef exists, and is a ConfigMap with a key named `ca.crt`.
		caCertRef := b.BackendTLSPolicy.Spec.Validation.CACertificateRefs[0]

		if caCertRef.Group != "" || caCertRef.Kind != "ConfigMap" {
			b.setRejectedConditions(ancestorRef, "Only ConfigMaps are supported for CA Certificate Refs",
				string(gatewayv1.BackendTLSPolicyReasonNoValidCACertificate), string(gatewayv1.BackendTLSPolicyReasonInvalidKind))
			return false, nil
		}

		caCertRefKey := types.NamespacedName{Name: string(caCertRef.Name), Namespace: b.BackendTLSPolicy.Namespace}
		caCert := &corev1.ConfigMap{}

		err := b.Client.Get(ctx, caCertRefKey, caCert)
		if err != nil {
			if k8serrors.IsNotFound(err) {
				b.setRejectedConditions(ancestorRef, fmt.Sprintf("CA Certificate does not exist: %s", caCertRefKey),
					string(gatewayv1.BackendTLSPolicyReasonNoValidCACertificate), string(gatewayv1.BackendTLSPolicyReasonInvalidCACertificateRef))
				return false, nil
			}
			scopedLog.ErrorContext(ctx, fmt.Sprintf("Failed trying to get CA Certificate Ref Configmap: %s", caCertRefKey), logfields.Error, err)
			// No point changing conditions, as returning this error will flow up to the reconciler, and status will not be updated.
			return false, err
		}

		if _, ok := caCert.Data["ca.crt"]; !ok {
			b.setRejectedConditions(ancestorRef, "CA Certificate ConfigMap does not contain a `ca.crt` key",
				string(gatewayv1.BackendTLSPolicyReasonNoValidCACertificate), string(gatewayv1.BackendTLSPolicyReasonInvalidCACertificateRef))
			return false, nil
		}
	}

	return true, nil
}

func (b *BackendTLSPolicyInput) setRejectedConditions(ancestorRef gatewayv1.ParentReference, message string, acceptedReason string, resolvedRefsReason string) {
	b.SetAncestorCondition(ancestorRef, metav1.Condition{
		Type:    string(gatewayv1.PolicyConditionAccepted),
		Status:  metav1.ConditionFalse,
		Reason:  acceptedReason,
		Message: message,
	})
	b.SetAncestorCondition(ancestorRef, metav1.Condition{
		Type:    string(gatewayv1.RouteConditionResolvedRefs),
		Status:  metav1.ConditionFalse,
		Reason:  resolvedRefsReason,
		Message: message,
	})
}
