// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package routechecks

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

// BackendValidator validates additional backend kinds without resolving endpoints.
// Built-in Service, ServiceImport, and InferencePool validation takes precedence.
type BackendValidator interface {
	// Supports is a pure capability check using the defaulted group and kind.
	Supports(schema.GroupKind) bool
	// Validate checks existence, configuration, and port semantics. namespace is
	// the effective backend namespace; ref retains its original fields.
	// A nil failure and error means valid. NotFound errors become BackendNotFound;
	// other errors retry reconciliation. Return no failure when returning an error.
	// Validation does not authorize references or check endpoint readiness.
	Validate(ctx context.Context, namespace string, ref gatewayv1.BackendObjectReference) (*BackendValidationFailure, error)
}

// BackendValidationFailure describes a permanent ResolvedRefs failure.
// Reason must be applicable to the ResolvedRefs condition.
type BackendValidationFailure struct {
	Reason  gatewayv1.RouteConditionReason
	Message string
}

func backendValidator(input Input, ref gatewayv1.BackendObjectReference) BackendValidator {
	if helpers.IsService(ref) || helpers.IsServiceImport(ref) || helpers.IsInferencePool(ref) {
		return nil
	}
	if extended, ok := input.(interface{ BackendValidator() BackendValidator }); ok {
		if validator := extended.BackendValidator(); validator != nil && validator.Supports(schema.GroupKind{
			Group: string(ptr.Deref(ref.Group, "")), Kind: string(ptr.Deref(ref.Kind, "Service")),
		}) {
			return validator
		}
	}
	return nil
}
