// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package routechecks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type testBackendValidator struct {
	failure *BackendValidationFailure
	err     error
	calls   int
	ns      string
	ref     gatewayv1.BackendObjectReference
}

func (*testBackendValidator) Supports(kind schema.GroupKind) bool {
	return kind == (schema.GroupKind{Group: "example.com", Kind: "Backend"})
}

func (v *testBackendValidator) Validate(_ context.Context, ns string, ref gatewayv1.BackendObjectReference) (*BackendValidationFailure, error) {
	v.calls++
	v.ns, v.ref = ns, ref
	return v.failure, v.err
}

type testBackendValidatorInput struct {
	Input
	validator BackendValidator
}

func (i testBackendValidatorInput) BackendValidator() BackendValidator { return i.validator }

func TestCustomBackendValidator(t *testing.T) {
	missing := k8serrors.NewNotFound(schema.GroupResource{Group: "example.com", Resource: "backends"}, "backend")
	timeout := k8serrors.NewTimeoutError("temporary failure", 1)
	failure := &BackendValidationFailure{Reason: gatewayv1.RouteReasonUnsupportedProtocol, Message: "backend requires TCP"}
	for _, tt := range []struct {
		name    string
		failure *BackendValidationFailure
		err     error
		reason  gatewayv1.RouteConditionReason
		message string
		wantErr bool
	}{
		{name: "valid backend without port"},
		{name: "validation failure", failure: failure, reason: failure.Reason, message: failure.Message},
		{name: "missing backend", err: missing, reason: gatewayv1.RouteReasonBackendNotFound, message: missing.Error()},
		{name: "retryable error", err: timeout, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ref := gatewayv1.BackendObjectReference{
				Group: ptr.To[gatewayv1.Group]("example.com"), Kind: ptr.To[gatewayv1.Kind]("Backend"), Name: "backend",
			}
			route := &gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Namespace: "route-ns", Generation: 1},
				Spec: gatewayv1.HTTPRouteSpec{Rules: []gatewayv1.HTTPRouteRule{{
					BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{BackendObjectReference: ref}}},
				}}},
			}
			validator := &testBackendValidator{failure: tt.failure, err: tt.err}
			input := testBackendValidatorInput{
				Input:     &HTTPRouteInput{Ctx: t.Context(), HTTPRoute: route, ControllerName: "test-controller"},
				validator: validator,
			}
			parent := gatewayv1.ParentReference{Name: "gateway"}
			ok, err := CheckBackend(input, parent)
			require.NoError(t, err)
			require.True(t, ok)
			require.Empty(t, route.Status.Parents)

			ok, err = CheckBackendIsExistingService(input, parent)
			require.Equal(t, 1, validator.calls)
			require.Equal(t, "route-ns", validator.ns)
			require.Equal(t, ref, validator.ref)
			if tt.wantErr {
				require.ErrorIs(t, err, tt.err)
				require.False(t, ok)
			} else {
				require.NoError(t, err)
				require.True(t, ok)
			}
			if tt.reason == "" {
				require.Empty(t, route.Status.Parents)
				return
			}
			require.Len(t, route.Status.Parents, 1)
			require.Len(t, route.Status.Parents[0].Conditions, 1)
			condition := route.Status.Parents[0].Conditions[0]
			require.Equal(t, string(gatewayv1.RouteConditionResolvedRefs), condition.Type)
			require.Equal(t, metav1.ConditionFalse, condition.Status)
			require.Equal(t, string(tt.reason), condition.Reason)
			require.Equal(t, tt.message, condition.Message)
		})
	}
}
