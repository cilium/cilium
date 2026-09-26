/*
Copyright 2025 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package kubernetes contains helper functions for interacting with
// Kubernetes objects within the conformance test suite.
package kubernetes

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapiconfig "sigs.k8s.io/gateway-api/conformance/utils/config"
	gatewayk8sutils "sigs.k8s.io/gateway-api/conformance/utils/kubernetes"

	inferenceapi "sigs.k8s.io/gateway-api-inference-extension/api/v1"
	"sigs.k8s.io/gateway-api-inference-extension/conformance/resources"
	"sigs.k8s.io/gateway-api-inference-extension/conformance/utils/config"
)

// checkConditions is a helper function similar to findConditionInList or CheckCondition
// from the Gateway API conformance utilities.
// It checks if one of the expectedConditions is present in the conditions list.
// If expectedCondition.Reason is an empty string, it matches any reason.
// Apart from a boolean value, if a match is found, checkConditions returns
// a pointer to the matched condition.
func checkConditions(t *testing.T, conditions []metav1.Condition, expectedConditions []metav1.Condition) (bool, *metav1.Condition) {
	t.Helper()
	for _, expectedCondition := range expectedConditions {
		for _, cond := range conditions {
			if cond.Type == expectedCondition.Type {
				if cond.Status == expectedCondition.Status {
					if expectedCondition.Reason == "" || cond.Reason == expectedCondition.Reason {
						return true, &expectedCondition
					}
					t.Logf("Condition %s found with Status %s, but Reason %s did not match expected %s",
						expectedCondition.Type, cond.Status, cond.Reason, expectedCondition.Reason)
				} else {
					t.Logf("Condition %s found, but Status %s did not match expected %s",
						expectedCondition.Type, cond.Status, expectedCondition.Status)
				}
			}
		}
		t.Logf("Condition %s with Status %s (and Reason %s if specified) not found in conditions list: %+v",
			expectedCondition.Type, expectedCondition.Status, expectedCondition.Reason, conditions)
	}
	return false, nil
}

// InferencePoolMustHaveCondition waits for the specified InferencePool resource
// to exist and report the expected status condition within one of its parent statuses.
// It polls the InferencePool's status until the condition is met or the timeout occurs.
func InferencePoolMustHaveCondition(t *testing.T, c client.Reader, poolNN types.NamespacedName, gateway types.NamespacedName, expectedCondition metav1.Condition) {
	t.Helper() // Marks this function as a test helper
	InferencePoolMustHaveOneOfConditions(t, c, poolNN, gateway, []metav1.Condition{expectedCondition})
}

// InferencePoolMustHaveCondition waits for the specified InferencePool resource
// to exist and report one of the expected status conditions within one of its parent statuses.
// It polls the InferencePool's status until one of the conditions is met or the timeout occurs.
func InferencePoolMustHaveOneOfConditions(t *testing.T, c client.Reader, poolNN types.NamespacedName, gateway types.NamespacedName, expectedConditions []metav1.Condition) {
	t.Helper() // Marks this function as a test helper

	var timeoutConfig = config.DefaultInferenceExtensionTimeoutConfig()
	var lastObservedPool *inferenceapi.InferencePool
	var lastError error
	var conditionFound bool
	var matchedExpectedCondition metav1.Condition

	waitErr := wait.PollUntilContextTimeout(
		context.Background(),
		timeoutConfig.InferencePoolMustHaveConditionInterval,
		timeoutConfig.GeneralMustHaveConditionTimeout,
		true, func(ctx context.Context) (bool, error) {
			pool := &inferenceapi.InferencePool{} // This is the type instance used for Get
			err := c.Get(ctx, poolNN, pool)
			if err != nil {
				if apierrors.IsNotFound(err) {
					t.Logf("InferencePool %s not found yet. Retrying.", poolNN.String())
					lastError = err
					return false, nil
				}
				t.Logf("Error fetching InferencePool %s (type: %s): %v. Retrying.", poolNN.String(), reflect.TypeOf(pool).String(), err)
				lastError = err
				return false, nil
			}
			lastObservedPool = pool
			lastError = nil
			conditionFound = false

			if len(pool.Status.Parents) == 0 {
				t.Logf("InferencePool %s has no parent statuses reported yet.", poolNN.String())
				return false, nil
			}

			for _, parentStatus := range pool.Status.Parents {
				if parentStatus.ParentRef.Namespace != "" &&
					string(parentStatus.ParentRef.Namespace) == gateway.Namespace &&
					string(parentStatus.ParentRef.Name) == gateway.Name {
					if ok, matched := checkConditions(t, parentStatus.Conditions, expectedConditions); ok {
						conditionFound = true
						matchedExpectedCondition = *matched
						return true, nil
					}
				}
			}
			return false, nil
		})

	if waitErr != nil || !conditionFound {
		debugMsg := ""
		if waitErr != nil {
			debugMsg += fmt.Sprintf(" Polling error: %v.", waitErr)
		}
		if lastError != nil {
			debugMsg += fmt.Sprintf(" Last error during fetching: %v.", lastError)
		}

		if lastObservedPool != nil {
			debugMsg += "\nLast observed InferencePool status:"
			if len(lastObservedPool.Status.Parents) == 0 {
				debugMsg += " (No parent statuses reported)"
			}
			builder := strings.Builder{}
			for i, parentStatus := range lastObservedPool.Status.Parents {
				namespace := parentStatus.ParentRef.Namespace
				if namespace == "" {
					namespace = inferenceapi.Namespace(poolNN.Namespace) // Fallback to the pool's namespace
				}
				fmt.Fprintf(&builder, "\n  Parent %d (Gateway: %s/%s):", i, namespace, parentStatus.ParentRef.Name)
				if len(parentStatus.Conditions) == 0 {
					builder.WriteString(" (No conditions reported for this parent)")
				}
				for _, cond := range parentStatus.Conditions {
					fmt.Fprintf(&builder, "\n    - Type: %s, Status: %s, Reason: %s, Message: %s", cond.Type, cond.Status, cond.Reason, cond.Message)
				}
			}
			debugMsg += builder.String()
		} else if lastError == nil || !apierrors.IsNotFound(lastError) {
			debugMsg += "\nInferencePool was not found or not observed successfully during polling."
		}

		var conditionStrings []string
		for _, cond := range expectedConditions {
			str := fmt.Sprintf("Type=%s, Status=%s", cond.Type, cond.Status)
			if cond.Reason != "" {
				str += fmt.Sprintf(", Reason='%s'", cond.Reason)
			}
			str = fmt.Sprintf("{%s}", str)
		}
		finalMsg := fmt.Sprintf("timed out or condition not met for InferencePool %s to have one of conditions {%s}",
			poolNN.String(), strings.Join(conditionStrings, ", "))
		finalMsg += "." + debugMsg
		require.FailNow(t, finalMsg)
	}

	logMsg := fmt.Sprintf("InferencePool %s successfully has condition Type=%s, Status=%s",
		poolNN.String(), matchedExpectedCondition.Type, matchedExpectedCondition.Status)
	if matchedExpectedCondition.Reason != "" {
		logMsg += fmt.Sprintf(", Reason='%s'", matchedExpectedCondition.Reason)
	}
	t.Log(logMsg)
}

// InferencePoolMustHaveNoParents waits for the specified InferencePool resource
// to exist and report that it has no parent references in its status.
// This typically indicates it is no longer referenced by any Gateway API resources.
func InferencePoolMustHaveNoParents(t *testing.T, c client.Reader, poolNN types.NamespacedName) {
	t.Helper()

	var lastObservedPool *inferenceapi.InferencePool
	var lastError error
	var timeoutConfig = config.DefaultInferenceExtensionTimeoutConfig()

	ctx := context.Background()
	waitErr := wait.PollUntilContextTimeout(
		ctx,

		timeoutConfig.InferencePoolMustHaveConditionInterval,
		timeoutConfig.GeneralMustHaveConditionTimeout,
		true,
		func(pollCtx context.Context) (bool, error) {
			pool := &inferenceapi.InferencePool{}
			err := c.Get(pollCtx, poolNN, pool)
			if err != nil {
				if apierrors.IsNotFound(err) {
					t.Logf("InferencePool %s not found. Considering this as having no parents.", poolNN.String())
					lastError = nil
					return true, nil
				}
				t.Logf("Error fetching InferencePool %s: %v. Retrying.", poolNN.String(), err)
				lastError = err
				return false, nil
			}
			lastObservedPool = pool
			lastError = nil

			if len(pool.Status.Parents) == 0 {
				t.Logf("InferencePool %s successfully has no parent statuses.", poolNN.String())
				return true, nil
			}
			t.Logf("InferencePool %s still has %d parent statuses. Waiting...", poolNN.String(), len(pool.Status.Parents))
			return false, nil
		})

	if waitErr != nil {
		debugMsg := fmt.Sprintf("Timed out waiting for InferencePool %s to have no parent statuses.", poolNN.String())
		if lastError != nil {
			debugMsg += fmt.Sprintf(" Last error during fetching: %v.", lastError)
		}
		if lastObservedPool != nil && len(lastObservedPool.Status.Parents) > 0 {
			debugMsg += fmt.Sprintf(" Last observed InferencePool still had %d parent(s):", len(lastObservedPool.Status.Parents))
		} else if lastError == nil && (lastObservedPool == nil || len(lastObservedPool.Status.Parents) == 0) {
			debugMsg += " Polling completed without timeout, but an unexpected waitErr occurred."
		}
		require.FailNow(t, debugMsg, waitErr)
	}
	t.Logf("Successfully verified that InferencePool %s has no parent statuses.", poolNN.String())
}

// HTTPRouteMustBeAcceptedAndResolved waits for the specified HTTPRoute
// to be Accepted and have its references resolved by the specified Gateway.
// It uses the upstream Gateway API's HTTPRouteMustHaveCondition helper.
func HTTPRouteMustBeAcceptedAndResolved(t *testing.T, c client.Client, timeoutConfig gatewayapiconfig.TimeoutConfig, routeNN, gatewayNN types.NamespacedName) {
	t.Helper()

	acceptedCondition := metav1.Condition{
		Type:   string(gatewayv1.RouteConditionAccepted),
		Status: metav1.ConditionTrue,
		Reason: string(gatewayv1.RouteReasonAccepted),
	}

	resolvedRefsCondition := metav1.Condition{
		Type:   string(gatewayv1.RouteConditionResolvedRefs),
		Status: metav1.ConditionTrue,
		Reason: string(gatewayv1.RouteReasonResolvedRefs),
	}

	t.Logf("Waiting for HTTPRoute %s to be Accepted by Gateway %s", routeNN.String(), gatewayNN.String())
	gatewayk8sutils.HTTPRouteMustHaveCondition(t, c, timeoutConfig, routeNN, gatewayNN, acceptedCondition)

	t.Logf("Waiting for HTTPRoute %s to have ResolvedRefs by Gateway %s", routeNN.String(), gatewayNN.String())
	gatewayk8sutils.HTTPRouteMustHaveCondition(t, c, timeoutConfig, routeNN, gatewayNN, resolvedRefsCondition)

	t.Logf("HTTPRoute %s is now Accepted and has ResolvedRefs by Gateway %s", routeNN.String(), gatewayNN.String())
}

// InferencePoolMustBeAcceptedByParent waits for the specified InferencePool
// to report an Accepted condition with status True and reason "Accepted"
// from the input Gateway.
func InferencePoolMustBeAcceptedByParent(t *testing.T, c client.Reader, poolNN, gatewayNN types.NamespacedName) {
	t.Helper()

	acceptedByParentCondition := metav1.Condition{
		Type:   string(gatewayv1.GatewayConditionAccepted),
		Status: metav1.ConditionTrue,
		Reason: string(gatewayv1.GatewayReasonAccepted), // Expecting the standard "Accepted" reason
	}

	t.Logf("Waiting for InferencePool %s to be Accepted by a parent Gateway (Reason: %s)", poolNN.String(), gatewayv1.GatewayReasonAccepted)
	InferencePoolMustHaveCondition(t, c, poolNN, gatewayNN, acceptedByParentCondition)
	t.Logf("InferencePool %s is Accepted by a parent Gateway (Reason: %s)", poolNN.String(), gatewayv1.GatewayReasonAccepted)
}

// HTTPRouteAndInferencePoolMustBeAcceptedAndRouteAccepted waits for the specified HTTPRoute
// to be Accepted and have its references resolved by the specified Gateway,
// AND for the specified InferencePool to be "RouteAccepted" using the specific
// RouteConditionAccepted criteria.
func HTTPRouteAndInferencePoolMustBeAcceptedAndRouteAccepted(
	t *testing.T,
	c client.Client,
	routeNN types.NamespacedName,
	gatewayNN types.NamespacedName,
	poolNN types.NamespacedName) {
	t.Helper()
	var timeoutConfig = config.DefaultInferenceExtensionTimeoutConfig()

	HTTPRouteMustBeAcceptedAndResolved(t, c, timeoutConfig.TimeoutConfig, routeNN, gatewayNN)
	InferencePoolMustBeAcceptedByParent(t, c, poolNN, gatewayNN)
	t.Logf("Successfully verified: HTTPRoute %s (Gateway %s) is Accepted & Resolved, and InferencePool %s is RouteAccepted.",
		routeNN.String(), gatewayNN.String(), poolNN.String())
}

// GetGatewayEndpoint waits for the specified Gateway to have at least one address
// and returns the address in "host:port" format.
// It leverages the upstream Gateway API's WaitForGatewayAddress.
func GetGatewayEndpoint(t *testing.T, k8sClient client.Client, timeoutConfig gatewayapiconfig.TimeoutConfig, gatewayNN types.NamespacedName) string {
	t.Helper()

	t.Logf("Waiting for Gateway %s/%s to get an address...", gatewayNN.Namespace, gatewayNN.Name)
	gwAddr, err := gatewayk8sutils.WaitForGatewayAddress(t, k8sClient, timeoutConfig, gatewayk8sutils.NewGatewayRef(gatewayNN))
	require.NoError(t, err, "failed to get Gateway address for %s", gatewayNN.String())
	require.NotEmpty(t, gwAddr, "Gateway %s has no address", gatewayNN.String())

	t.Logf("Gateway %s/%s has address: %s", gatewayNN.Namespace, gatewayNN.Name, gwAddr)
	return gwAddr
}

// GetPodsWithLabel retrieves a list of Pods.
// It finds pods matching the given labels in a specific namespace.
func GetPodsWithLabel(t *testing.T, c client.Reader, namespace string, labels map[string]string, timeConfig gatewayapiconfig.TimeoutConfig) ([]corev1.Pod, error) {
	t.Helper()

	pods := &corev1.PodList{}
	timeout := timeConfig.RequestTimeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	listOptions := []client.ListOption{
		client.InNamespace(namespace),
		client.MatchingLabels(labels),
	}

	t.Logf("Searching for Pods with labels %v in namespace %s", labels, namespace)
	waitErr := wait.PollUntilContextTimeout(ctx, 1*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		if err := c.List(context.Background(), pods, listOptions...); err != nil {
			return false, fmt.Errorf("failed to list pods with labels '%v' in namespace '%s': %w", labels, namespace, err)
		}
		if len(pods.Items) > 0 {
			for _, pod := range pods.Items {
				if pod.Status.PodIP == "" || pod.Status.Phase != corev1.PodRunning {
					t.Logf("Pod %s found, but not yet running or has no IP. Current phase: %s, IP: '%s'. Retrying.", pod.Name, pod.Status.Phase, pod.Status.PodIP)
					return false, nil
				}
			}
			return true, nil
		}
		t.Logf("No pods found with selector %v yet. Retrying.", labels)
		return false, nil
	})
	return pods.Items, waitErr
}

// MakeServiceUnavailable modifies a Service's selector to make it temporarily unavailable.
// It returns a cleanup function to restore the original selector and ensure the test state is clean.
func MakeServiceUnavailable(t *testing.T, c client.Client, serviceRef types.NamespacedName, timeout time.Duration) (func(), error) {
	t.Helper()

	ctx := context.Background()
	svc := &corev1.Service{}

	t.Logf("Making Service %s/%s unavailable by modifying its selector...", serviceRef.Namespace, serviceRef.Name)
	if err := c.Get(ctx, serviceRef, svc); err != nil {
		return nil, fmt.Errorf("failed to get Service %s/%s: %w", serviceRef.Namespace, serviceRef.Name, err)
	}
	originalSelector := svc.Spec.Selector
	svc.Spec.Selector = map[string]string{"app": "do-not-match-for-testing"}
	if err := c.Update(ctx, svc); err != nil {
		return nil, fmt.Errorf("failed to update selector for Service %s/%s: %w", serviceRef.Namespace, serviceRef.Name, err)
	}

	t.Logf("Waiting for EndpointSlices of Service %s/%s to become empty...", serviceRef.Namespace, serviceRef.Name)
	err := waitNumberOfEndpointsForService(ctx, c, serviceRef, 0, timeout)
	if err != nil {
		return nil, fmt.Errorf("timed out waiting for EndpointSlices of Service %s/%s to become empty: %w", serviceRef.Namespace, serviceRef.Name, err)
	}
	t.Logf("Successfully modified selector for Service %s/%s", serviceRef.Namespace, serviceRef.Name)

	cleanupFunc := func() {
		t.Helper()
		t.Logf("Restoring original selector for Service %s/%s...", serviceRef.Namespace, serviceRef.Name)

		restorationCtx := context.Background()
		svcToRestore := &corev1.Service{}

		if err := c.Get(restorationCtx, serviceRef, svcToRestore); err != nil {
			t.Fatalf("Cleanup failed: could not get Service %s/%s for restoration: %v", serviceRef.Namespace, serviceRef.Name, err)
		}

		svcToRestore.Spec.Selector = originalSelector
		if err := c.Update(restorationCtx, svcToRestore); err != nil {
			t.Fatalf("Cleanup failed: could not restore original selector for Service %s/%s: %v", serviceRef.Namespace, serviceRef.Name, err)
		}

		t.Logf("Waiting for EndpointSlices of Service %s/%s to be restored...", serviceRef.Namespace, serviceRef.Name)
		err := waitNumberOfEndpointsForService(restorationCtx, c, serviceRef, resources.EndPointPickerPodReplicas, timeout)
		if err != nil {
			t.Fatalf("Cleanup failed: timed out waiting for EndpointSlices of Service %s/%s to be restored: %v", serviceRef.Namespace, serviceRef.Name, err)
		}
		t.Logf("Successfully restored selector for Service %s/%s", serviceRef.Namespace, serviceRef.Name)
	}
	return cleanupFunc, nil
}

func waitNumberOfEndpointsForService(ctx context.Context, c client.Client, serviceRef types.NamespacedName, wantNum int, timeout time.Duration) error {
	err := wait.PollUntilContextTimeout(ctx, 1*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		endpointSliceList := &discoveryv1.EndpointSliceList{}
		if err := c.List(ctx, endpointSliceList,
			client.InNamespace(serviceRef.Namespace),
			client.MatchingLabels{discoveryv1.LabelServiceName: serviceRef.Name},
		); err != nil {
			return false, fmt.Errorf("failed to list EndpointSlices for Service %s: %w", serviceRef.Name, err)
		}
		totalEndpoints := 0
		for _, slice := range endpointSliceList.Items {
			totalEndpoints += len(slice.Endpoints)
		}
		if totalEndpoints == wantNum {
			return true, nil
		}
		return false, nil
	})
	return err
}
