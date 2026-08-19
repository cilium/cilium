// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/policychecks"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// BackendTLSPolicyStatusManager calculates and writes BackendTLSPolicy status.
type BackendTLSPolicyStatusManager struct {
	client         client.Client
	controllerName string
}

func NewBackendTLSPolicyStatusManager(client client.Client, controllerName string) *BackendTLSPolicyStatusManager {
	return &BackendTLSPolicyStatusManager{
		client:         client,
		controllerName: controllerName,
	}
}

// SetBackendTLSPolicyStatuses updates BackendTLSPolicy status for the current
// Gateway and mutates btlspMap to reflect validation results. Policies that
// fail spec validation are moved from Valid to Invalid so later ingestion can
// distinguish a broken policy from the absence of a policy.
func (m *BackendTLSPolicyStatusManager) SetBackendTLSPolicyStatuses(
	scopedLog *slog.Logger,
	ctx context.Context,
	httpRoutes []gatewayv1.HTTPRoute,
	btlspMap helpers.BackendTLSPolicyServiceMap,
	gatewayName types.NamespacedName,
) error {
	scopedLog.Debug("Updating BackendTLSPolicy statuses for Gateway", policies, len(btlspMap))

	currentGatewayRef := gatewayv1.ParentReference{
		Group:     ptr.To[gatewayv1.Group](gatewayv1.GroupName),
		Kind:      ptr.To[gatewayv1.Kind]("Gateway"),
		Namespace: (*gatewayv1.Namespace)(&gatewayName.Namespace),
		Name:      gatewayv1.ObjectName(gatewayName.Name),
	}

	// TODO(youngnick): There's currently a corner case error in the design upstream,
	// as there is no way to solve for the case that:
	// * A BackendTLSPolicy has multiple targetRefs
	// * the multiple targetRefs point to backends used in HTTPRoutes that roll up to the same
	//   Gateway
	// * Some of the targetRefs exist and some do not.
	//
	// What happens in this case is currently undefined upstream, as we only namespace the BackendTLSPolicy
	// status by Gateway.
	//
	// This code currently errs on the side of marking the BackendTLSPolicy as Accepted,
	// with ResolvedRefs: False, as long as at least one targetRef is valid, and there are
	// other targetRefs that are not valid.

	// confirmedValidBTLSPs maintains a set of all BackendTLSPolicies that
	// have at least one targetRef that is valid for the currentGatewayRef.
	//
	// This map will only be populated if at least one of the targetRefs in that
	// Policy passes all the checks and is valid.
	//
	// This is then used both as a flag to see if other targetRefs in the same
	// Policy should create status updates or not.
	confirmedValidBTLSPs := make(map[types.NamespacedName]struct{})

	// svcNames have already had the conflict-resolution rules applied to build the btlspMap.
	// So, we can rely both on them being correct, and being referenced in the BackendTLSPolicy.
	// For each svcName, check if that service rolls up to a relevant Gateway
	// and run any required Policy checks, like if the Service exists.
	for svcName, collection := range btlspMap {
		// We have to find if BackendTLSPolicy is used in the current Gateway, so we can set the
		// status.

		// First, we get all the HTTPRoutes that have the targetRef service as a backend
		hrList := &gatewayv1.HTTPRouteList{}

		if err := m.client.List(ctx, hrList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.BackendServiceHTTPRouteIndex, svcName.String()),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get related HTTPRoutes", logfields.Error, err)
			return err
		}

		found, err := helpers.ContainsCommonHTTPRoute(hrList.Items, httpRoutes)
		if err != nil {
			// There was a common HTTPRoute found, but the generation was different, error out from this.
			scopedLog.ErrorContext(ctx, "Different generation comparing a HTTPRoute, re-reconciling", logfields.Error, err)
			return err
		}
		// The BackendServiceHTTPRouteIndex only covers backendRefs; ext_authz
		// backends are checked directly from the already loaded HTTPRoutes.
		if !found {
			for _, hr := range httpRoutes {
				for _, rule := range hr.Spec.Rules {
					for _, f := range rule.Filters {
						if f.Type != gatewayv1.HTTPRouteFilterExternalAuth || f.ExternalAuth == nil {
							continue
						}
						ns := helpers.NamespaceDerefOr(f.ExternalAuth.BackendRef.Namespace, hr.Namespace)
						if string(f.ExternalAuth.BackendRef.Name) == svcName.Name && ns == svcName.Namespace {
							found = true
						}
					}
				}
			}
		}
		if !found {
			// This service is not used in the current Gateway, so we can skip it.
			continue
		}

		// next thing, see if the referenced service exists. If not, we can just reject all the
		// BackendTLSPolicies regardless of which one got accepted.
		obj := &corev1.Service{}
		err = m.client.Get(ctx, svcName, obj)
		if err != nil {
			if !k8serrors.IsNotFound(err) {
				// if it is not just a not found error, we should return the error as something is bad
				return fmt.Errorf("error while checking Backend Service: %w", err)
			}
			// If the Service does not exist, all referenced BackendTLSPolicies must be
			// Accepted: False, with reason Conflicted.
			for _, original := range collection.Valid {
				btlspFullName := client.ObjectKeyFromObject(original)

				if _, ok := confirmedValidBTLSPs[btlspFullName]; ok {
					// If the BackendTLSPolicy is already listed in the btlspStatus,
					// then we've already confirmed it's valid, so we need to skip updating
					// the status with errors.
					continue
				}

				btlsp := original.DeepCopy()

				input := &policychecks.BackendTLSPolicyInput{
					Client:           m.client,
					BackendTLSPolicy: btlsp,
					ControllerName:   m.controllerName,
				}
				input.SetAncestorCondition(currentGatewayRef, metav1.Condition{
					Type:    string(gatewayv1.PolicyConditionAccepted),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.PolicyReasonInvalid),
					Message: fmt.Sprintf("TargetRef does not exist: %s", svcName),
				})
				input.SetAncestorCondition(currentGatewayRef, metav1.Condition{
					Type:    string(gatewayv1.RouteConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.RouteReasonBackendNotFound),
					Message: fmt.Sprintf("TargetRef does not exist: %s", svcName),
				})
				// Checks finished, apply the status to the actual objects.
				if err := m.updateBackendTLSPolicyStatus(ctx, scopedLog, original, btlsp); err != nil {
					return fmt.Errorf("failed to update BackendTLSPolicy status: %w", err)
				}
				// Update the original with the updated status
				original.Status = btlsp.Status
			}

			// Second, for any Conflicted BackendTLSPolicies, we can set them to Conflicted and move on.
			for _, original := range collection.Conflicted {
				btlspFullName := types.NamespacedName{
					Name:      original.GetName(),
					Namespace: original.GetNamespace(),
				}

				if _, ok := confirmedValidBTLSPs[btlspFullName]; ok {
					// If the BackendTLSPolicy is already listed in the btlspStatus,
					// then we've already confirmed it's valid, so we need to skip updating
					// the status with errors.
					continue
				}

				btlsp := original.DeepCopy()

				input := &policychecks.BackendTLSPolicyInput{
					Client:           m.client,
					BackendTLSPolicy: btlsp,
					ControllerName:   m.controllerName,
				}
				input.SetAncestorCondition(currentGatewayRef, metav1.Condition{
					Type:    string(gatewayv1.PolicyConditionAccepted),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.PolicyReasonInvalid),
					Message: fmt.Sprintf("TargetRef does not exist: %s", svcName),
				})
				input.SetAncestorCondition(currentGatewayRef, metav1.Condition{
					Type:    string(gatewayv1.RouteConditionResolvedRefs),
					Status:  metav1.ConditionFalse,
					Reason:  string(gatewayv1.RouteReasonBackendNotFound),
					Message: fmt.Sprintf("TargetRef does not exist: %s", svcName),
				})
				// Checks finished, apply the status to the actual objects.
				if err := m.updateBackendTLSPolicyStatus(ctx, scopedLog, original, btlsp); err != nil {
					return fmt.Errorf("failed to update BackendTLSPolicy status: %w", err)
				}
				// Update the original with the updated status
				original.Status = btlsp.Status
			}

			// Continue, because this Service doesn't exist
			continue
		}

		// Lastly, pull out any valid BackendTLSPolicies, then check them.
		// Policies that fail validation are moved from Valid to Invalid so
		// the ingestion logic can distinguish "no policy" from "broken policy".
		for sectionName, original := range collection.Valid {
			btlsp := original.DeepCopy()

			inputLogger := scopedLog.With(logfields.BackendTLSPolicyName, client.ObjectKeyFromObject(btlsp))
			// input for the validators
			// The validators will mutate the BackendTLSPolicy as required, setting its status correctly.
			input := &policychecks.BackendTLSPolicyInput{
				Client:           m.client,
				BackendTLSPolicy: btlsp,
				ControllerName:   m.controllerName,
			}

			// Now, we run the Policy checks against it, which will update the status correctly.

			// So we can update the status of that BackendTLSPolicy with the name of the current Gateway.

			// set Accepted to okay, this will be overwritten in checks if needed
			input.SetAncestorCondition(currentGatewayRef, metav1.Condition{
				Type:    string(gatewayv1.PolicyConditionAccepted),
				Status:  metav1.ConditionTrue,
				Reason:  string(gatewayv1.PolicyReasonAccepted),
				Message: "Accepted BackendTLSPolicy",
			})
			// set ResolvedRefs to okay, this wil be overwritten in checks if needed
			input.SetAncestorCondition(currentGatewayRef, metav1.Condition{
				Type:    string(gatewayv1.RouteConditionResolvedRefs),
				Status:  metav1.ConditionTrue,
				Reason:  string(gatewayv1.RouteReasonResolvedRefs),
				Message: "All references are valid",
			})
			inputLogger.Debug("Validating BackendTLSPolicy spec")
			valid, err := input.ValidateSpec(ctx, inputLogger, currentGatewayRef)
			if err != nil {
				return fmt.Errorf("failed to validate BackendTLSPolicy spec: %w", err)
			}
			if valid {
				// This BackendTLSPolicy is valid, so we can add the original status to the btlspStatus
				// lookup map. It's okay to do this multiple times, since the original status will be the same.
				confirmedValidBTLSPs[types.NamespacedName{
					Name:      btlsp.GetName(),
					Namespace: btlsp.GetNamespace(),
				}] = struct{}{}
			} else {
				// This BackendTLSPolicy is invalid, so it should be removed from the valid
				// map and added to the invalid map to ensure it's not used by the
				// ingestion logic.
				collection.DeleteValidPolicy(sectionName)
				collection.UpsertInvalidPolicy(sectionName, original)
			}

			// Checks finished, apply the status to the actual objects.
			if err := m.updateBackendTLSPolicyStatus(ctx, scopedLog, original, btlsp); err != nil {
				return fmt.Errorf("failed to update BackendTLSPolicy status: %w", err)
			}
			// Update the original with the updated status
			original.Status = btlsp.Status
		}

		// We can set Conflicted BTLSPs conditions now.
		for _, original := range collection.Conflicted {
			btlsp := original.DeepCopy()

			// input for the validators
			// The validators will mutate the BackendTLSPolicy as required, setting its status correctly.
			input := &policychecks.BackendTLSPolicyInput{
				Client:           m.client,
				BackendTLSPolicy: btlsp,
				ControllerName:   m.controllerName,
			}

			input.SetAncestorCondition(currentGatewayRef, metav1.Condition{
				Type:    string(gatewayv1.PolicyConditionAccepted),
				Status:  metav1.ConditionFalse,
				Reason:  string(gatewayv1.PolicyReasonConflicted),
				Message: "BackendTLSPolicy conflicts with another",
			})
			// Checks finished, apply the status to the actual objects.
			if err := m.updateBackendTLSPolicyStatus(ctx, scopedLog, original, btlsp); err != nil {
				return fmt.Errorf("failed to update BackendTLSPolicy status: %w", err)
			}
			// Update the original with the updated status
			original.Status = btlsp.Status
		}
	}

	return nil
}

func (m *BackendTLSPolicyStatusManager) updateBackendTLSPolicyStatus(ctx context.Context, scopedLog *slog.Logger, original *gatewayv1.BackendTLSPolicy, new *gatewayv1.BackendTLSPolicy) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	if cmp.Equal(oldStatus, newStatus, cmpopts.IgnoreFields(metav1.Condition{}, lastTransitionTime)) {
		return nil
	}
	scopedLog.Debug("BackendTLSPolicy status", backendTLSPolicy, types.NamespacedName{Name: original.Name, Namespace: original.Namespace})
	return m.client.Status().Update(ctx, new)
}
