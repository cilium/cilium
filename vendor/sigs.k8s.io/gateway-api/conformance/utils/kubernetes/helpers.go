/*
Copyright 2022 The Kubernetes Authors.

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

package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/apis/v1alpha2"
	"sigs.k8s.io/gateway-api/conformance/utils/config"
	"sigs.k8s.io/gateway-api/conformance/utils/tlog"
)

// GatewayExcludedFromReadinessChecks is an annotation that can be placed on a
// Gateway provided via the tests to indicate that it is NOT expected to be
// Accepted or Provisioned in its default state. This is generally helpful for
// tests which validate fixing broken Gateways, e.t.c.
const GatewayExcludedFromReadinessChecks = "gateway-api/skip-this-for-readiness"

// GatewayRef is a tiny type for specifying an HTTP Route ParentRef without
// relying on a specific api version.
type GatewayRef struct {
	types.NamespacedName
	listenerNames []*gatewayv1.SectionName
}

// NewGatewayRef creates a GatewayRef resource.  ListenerNames are optional.
func NewGatewayRef(nn types.NamespacedName, listenerNames ...string) GatewayRef {
	var listeners []*gatewayv1.SectionName

	if len(listenerNames) == 0 {
		listenerNames = append(listenerNames, "")
	}

	for _, listener := range listenerNames {
		sectionName := gatewayv1.SectionName(listener)
		listeners = append(listeners, &sectionName)
	}
	return GatewayRef{
		NamespacedName: nn,
		listenerNames:  listeners,
	}
}

// GWCMustHaveAcceptedConditionTrue waits until the specified GatewayClass has an Accepted condition set with a status value equal to True.
func GWCMustHaveAcceptedConditionTrue(t *testing.T, c client.Client, timeoutConfig config.TimeoutConfig, gwcName string) string {
	return gwcMustBeAccepted(t, c, timeoutConfig, gwcName, string(metav1.ConditionTrue))
}

// GWCMustHaveAcceptedConditionAny waits until the specified GatewayClass has an Accepted condition set with a status set to any value.
func GWCMustHaveAcceptedConditionAny(t *testing.T, c client.Client, timeoutConfig config.TimeoutConfig, gwcName string) string {
	return gwcMustBeAccepted(t, c, timeoutConfig, gwcName, "")
}

// gwcMustBeAccepted waits until the specified GatewayClass has an Accepted
// condition set. Passing an empty status string means that any value
// will be accepted. It also returns the ControllerName for the GatewayClass.
// This will cause the test to halt if the specified timeout is exceeded.
func gwcMustBeAccepted(t *testing.T, c client.Client, timeoutConfig config.TimeoutConfig, gwcName, expectedStatus string) string {
	t.Helper()

	var controllerName string
	waitErr := wait.PollUntilContextTimeout(context.Background(), 1*time.Second, timeoutConfig.GWCMustBeAccepted, true, func(ctx context.Context) (bool, error) {
		gwc := &gatewayv1.GatewayClass{}
		err := c.Get(ctx, types.NamespacedName{Name: gwcName}, gwc)
		if err != nil {
			return false, fmt.Errorf("error fetching GatewayClass: %w", err)
		}

		controllerName = string(gwc.Spec.ControllerName)

		if err := ConditionsHaveLatestObservedGeneration(gwc, gwc.Status.Conditions); err != nil {
			tlog.Log(t, "GatewayClass", err)
			return false, nil
		}

		// Passing an empty string as the Reason means that any Reason will do.
		return findConditionInList(t, gwc.Status.Conditions, "Accepted", expectedStatus, ""), nil
	})
	require.NoErrorf(t, waitErr, "error waiting for %s GatewayClass to have Accepted condition to be set: %v", gwcName, waitErr)

	return controllerName
}

// GatewayMustHaveLatestConditions waits until the specified Gateway has
// all conditions updated with the latest observed generation.
func GatewayMustHaveLatestConditions(t *testing.T, c client.Client, timeoutConfig config.TimeoutConfig, gwNN types.NamespacedName) {
	t.Helper()

	waitErr := wait.PollUntilContextTimeout(context.Background(), 1*time.Second, timeoutConfig.LatestObservedGenerationSet, true, func(ctx context.Context) (bool, error) {
		gw := &gatewayv1.Gateway{}
		err := c.Get(ctx, gwNN, gw)
		if err != nil {
			return false, fmt.Errorf("error fetching Gateway: %w", err)
		}

		if err := ConditionsHaveLatestObservedGeneration(gw, gw.Status.Conditions); err != nil {
			tlog.Logf(t, "Gateway %s latest conditions not set yet: %v", gwNN.String(), err)
			return false, nil
		}

		return true, nil
	})

	require.NoErrorf(t, waitErr, "error waiting for Gateway %s to have Latest ObservedGeneration to be set: %v", gwNN.String(), waitErr)
}

// GatewayClassMustHaveLatestConditions will fail the test if there are
// conditions that were not updated
func GatewayClassMustHaveLatestConditions(t *testing.T, gwc *gatewayv1.GatewayClass) {
	t.Helper()

	if err := ConditionsHaveLatestObservedGeneration(gwc, gwc.Status.Conditions); err != nil {
		tlog.Fatalf(t, "GatewayClass %v", err)
	}
}

// HTTPRouteMustHaveLatestConditions will fail the test if there are
// conditions that were not updated
func HTTPRouteMustHaveLatestConditions(t *testing.T, r *gatewayv1.HTTPRoute) {
	t.Helper()

	for _, parent := range r.Status.Parents {
		if err := ConditionsHaveLatestObservedGeneration(r, parent.Conditions); err != nil {
			tlog.Fatalf(t, "HTTPRoute(controller=%v, parentRef=%#v) %v", parent.ControllerName, parent, err)
		}
	}
}

func ConditionsHaveLatestObservedGeneration(obj metav1.Object, conditions []metav1.Condition) error {
	staleConditions := FilterStaleConditions(obj, conditions)

	if len(staleConditions) == 0 {
		return nil
	}

	wantGeneration := obj.GetGeneration()
	var b strings.Builder
	fmt.Fprintf(&b, "expected observedGeneration to be updated to %d for all conditions", wantGeneration)
	fmt.Fprintf(&b, ", only %d/%d were updated.", len(conditions)-len(staleConditions), len(conditions))
	fmt.Fprintf(&b, " stale conditions are: ")

	for i, c := range staleConditions {
		fmt.Fprintf(&b, "%s (generation %d)", c.Type, c.ObservedGeneration)
		if i != len(staleConditions)-1 {
			fmt.Fprintf(&b, ", ")
		}
	}

	return errors.New(b.String())
}

// FilterStaleConditions returns the list of status condition whose observedGeneration does not
// match the object's metadata.Generation
func FilterStaleConditions(obj metav1.Object, conditions []metav1.Condition) []metav1.Condition {
	stale := make([]metav1.Condition, 0, len(conditions))
	for _, condition := range conditions {
		if obj.GetGeneration() != condition.ObservedGeneration {
			stale = append(stale, condition)
		}
	}
	return stale
}

// NamespacesMustBeReady waits until all Pods are marked Ready and all Gateways
// are marked Accepted and Programmed in the specified namespace(s). This will
// cause the test to halt if the specified timeout is exceeded.
func NamespacesMustBeReady(t *testing.T, c client.Client, timeoutConfig config.TimeoutConfig, namespaces []string) {
	t.Helper()

	waitErr := wait.PollUntilContextTimeout(context.Background(), 1*time.Second, timeoutConfig.NamespacesMustBeReady, true, func(ctx context.Context) (bool, error) {
		for _, ns := range namespaces {
			gwList := &gatewayv1.GatewayList{}
			err := c.List(ctx, gwList, client.InNamespace(ns))
			if err != nil {
				tlog.Errorf(t, "Error listing Gateways: %v", err)
			}
			for _, gw := range gwList.Items {
				if val, ok := gw.Annotations[GatewayExcludedFromReadinessChecks]; ok && val == "true" {
					tlog.Logf(t, "Gateway %s is skipped for setup and wont be tested", client.ObjectKeyFromObject(&gw))
					continue
				}

				if err = ConditionsHaveLatestObservedGeneration(&gw, gw.Status.Conditions); err != nil {
					tlog.Logf(t, "Gateway %s %v", client.ObjectKeyFromObject(&gw), err)
					return false, nil
				}

				// Passing an empty string as the Reason means that any Reason will do.
				if !findConditionInList(t, gw.Status.Conditions, string(gatewayv1.GatewayConditionAccepted), "True", "") {
					tlog.Logf(t, "%s Gateway not Accepted yet", client.ObjectKeyFromObject(&gw))
					return false, nil
				}

				// Passing an empty string as the Reason means that any Reason will do.
				if !findConditionInList(t, gw.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed), "True", "") {
					tlog.Logf(t, "%s Gateway not Programmed yet", client.ObjectKeyFromObject(&gw))
					return false, nil
				}
			}

			podList := &v1.PodList{}
			err = c.List(ctx, podList, client.InNamespace(ns))
			if err != nil {
				tlog.Errorf(t, "Error listing Pods: %v", err)
			}
			for _, pod := range podList.Items {
				if !findPodConditionInList(t, pod.Status.Conditions, "Ready", "True") &&
					pod.Status.Phase != v1.PodSucceeded &&
					pod.DeletionTimestamp == nil {
					tlog.Logf(t, "Pod %s not ready yet", client.ObjectKeyFromObject(&pod))
					return false, nil
				}
			}
		}
		tlog.Logf(t, "Gateways and Pods in %s namespaces ready", strings.Join(namespaces, ", "))
		return true, nil
	})
	require.NoErrorf(t, waitErr, "error waiting for %s namespaces to be ready", strings.Join(namespaces, ", "))
}

// GatewayMustHaveCondition checks that the supplied Gateway has the supplied Condition,
// halting after the specified timeout is exceeded.
func GatewayMustHaveCondition(
	t *testing.T,
	client client.Client,
	timeoutConfig config.TimeoutConfig,
	gwNN types.NamespacedName,
	expectedCondition metav1.Condition,
) {
	t.Helper()

	waitErr := wait.PollUntilContextTimeout(
		context.Background(),
		1*time.Second,
		timeoutConfig.GatewayMustHaveCondition,
		true,
		func(ctx context.Context) (bool, error) {
			gw := &gatewayv1.Gateway{}
			err := client.Get(ctx, gwNN, gw)
			if err != nil {
				return false, fmt.Errorf("error fetching Gateway: %w", err)
			}

			if err := ConditionsHaveLatestObservedGeneration(gw, gw.Status.Conditions); err != nil {
				return false, err
			}

			if findConditionInList(t,
				gw.Status.Conditions,
				expectedCondition.Type,
				string(expectedCondition.Status),
				expectedCondition.Reason,
			) {
				return true, nil
			}

			return false, nil
		},
	)

	require.NoErrorf(t, waitErr, "error waiting for Gateway status to have a Condition matching expectations")
}

// MeshNamespacesMustBeReady waits until all Pods are marked Ready. This is
// intended to be used for mesh tests and does not require any Gateways to
// exist. This will cause the test to halt if the specified timeout is exceeded.
func MeshNamespacesMustBeReady(t *testing.T, c client.Client, timeoutConfig config.TimeoutConfig, namespaces []string) {
	t.Helper()

	waitErr := wait.PollUntilContextTimeout(context.Background(), 1*time.Second, timeoutConfig.NamespacesMustBeReady, true, func(ctx context.Context) (bool, error) {
		for _, ns := range namespaces {
			podList := &v1.PodList{}
			err := c.List(ctx, podList, client.InNamespace(ns))
			if err != nil {
				tlog.Errorf(t, "Error listing Pods: %v", err)
			}
			for _, pod := range podList.Items {
				if !findPodConditionInList(t, pod.Status.Conditions, "Ready", "True") &&
					pod.Status.Phase != v1.PodSucceeded &&
					pod.DeletionTimestamp == nil {
					tlog.Logf(t, "Pod %s not ready yet", client.ObjectKeyFromObject(&pod))
					return false, nil
				}
			}
		}
		tlog.Logf(t, "Pods in %s namespaces ready", strings.Join(namespaces, ", "))
		return true, nil
	})
	require.NoErrorf(t, waitErr, "error waiting for %s namespaces to be ready", strings.Join(namespaces, ", "))
}

// GatewayAndRoutesMustBeAccepted waits until:
//  1. The specified Gateway has an IP address assigned to it.
//  2. The route has a ParentRef referring to the Gateway.
//  3. All the gateway's listeners have the following conditions set to true:
//     - ListenerConditionResolvedRefs
//     - ListenerConditionAccepted
//     - ListenerConditionProgrammed
//
// The test will fail if these conditions are not met before the timeouts.
func GatewayAndRoutesMustBeAccepted(t *testing.T, c client.Client, timeoutConfig config.TimeoutConfig, controllerName string, gw GatewayRef, routeType any, routeNNs ...types.NamespacedName) string {
	t.Helper()

	RouteTypeMustHaveParentsField(t, routeType)
	gwAddr, err := WaitForGatewayAddress(t, c, timeoutConfig, gw)

	require.NoErrorf(t, err, "timed out waiting for Gateway address to be assigned")

	ns := gatewayv1.Namespace(gw.Namespace)
	kind := gatewayv1.Kind("Gateway")

	for _, routeNN := range routeNNs {
		namespaceRequired := true
		if routeNN.Namespace == gw.Namespace {
			namespaceRequired = false
		}

		var parents []gatewayv1.RouteParentStatus
		for _, listener := range gw.listenerNames {
			parents = append(parents, gatewayv1.RouteParentStatus{
				ParentRef: gatewayv1.ParentReference{
					Group:       (*gatewayv1.Group)(&gatewayv1.GroupVersion.Group),
					Kind:        &kind,
					Name:        gatewayv1.ObjectName(gw.Name),
					Namespace:   &ns,
					SectionName: listener,
				},
				ControllerName: gatewayv1.GatewayController(controllerName),
				Conditions: []metav1.Condition{{
					Type:   string(gatewayv1.RouteConditionAccepted),
					Status: metav1.ConditionTrue,
					Reason: string(gatewayv1.RouteReasonAccepted),
				}},
			})
		}
		RouteMustHaveParents(t, c, timeoutConfig, routeNN, parents, namespaceRequired, routeType)
	}

	requiredListenerConditions := []metav1.Condition{
		{
			Type:   string(gatewayv1.ListenerConditionResolvedRefs),
			Status: metav1.ConditionTrue,
			Reason: "", // any reason
		},
		{
			Type:   string(gatewayv1.ListenerConditionAccepted),
			Status: metav1.ConditionTrue,
			Reason: "", // any reason
		},
		{
			Type:   string(gatewayv1.ListenerConditionProgrammed),
			Status: metav1.ConditionTrue,
			Reason: "", // any reason
		},
	}
	GatewayListenersMustHaveConditions(t, c, timeoutConfig, gw.NamespacedName, requiredListenerConditions)

	return gwAddr
}

// GatewayAndHTTPRoutesMustBeAccepted waits until:
//  1. The specified Gateway has an IP address assigned to it.
//  2. The route has a ParentRef referring to the Gateway.
//  3. All the gateway's listeners have the following conditions set to true:
//     - ListenerConditionResolvedRefs
//     - ListenerConditionAccepted
//     - ListenerConditionProgrammed
//
// The test will fail if these conditions are not met before the timeouts.
func GatewayAndHTTPRoutesMustBeAccepted(t *testing.T, c client.Client, timeoutConfig config.TimeoutConfig, controllerName string, gw GatewayRef, routeNNs ...types.NamespacedName) string {
	return GatewayAndRoutesMustBeAccepted(t, c, timeoutConfig, controllerName, gw, &gatewayv1.HTTPRoute{}, routeNNs...)
}

// GatewayAndUDPRoutesMustBeAccepted waits until the specified Gateway has an IP
// address assigned to it and the UDPRoute has a ParentRef referring to the
// Gateway. The test will fail if these conditions are not met before the
// timeouts.
func GatewayAndUDPRoutesMustBeAccepted(t *testing.T, c client.Client, timeoutConfig config.TimeoutConfig, controllerName string, gw GatewayRef, routeNNs ...types.NamespacedName) string {
	return GatewayAndRoutesMustBeAccepted(t, c, timeoutConfig, controllerName, gw, &v1alpha2.UDPRoute{}, routeNNs...)
}

// WaitForGatewayAddress waits until at least one IP Address has been set in the
// status of the specified Gateway.
func WaitForGatewayAddress(t *testing.T, client client.Client, timeoutConfig config.TimeoutConfig, gwRef GatewayRef) (string, error) {
	t.Helper()

	var ipAddr, port string
	waitErr := wait.PollUntilContextTimeout(context.Background(), 1*time.Second, timeoutConfig.GatewayMustHaveAddress, true, func(ctx context.Context) (bool, error) {
		gw := &gatewayv1.Gateway{}
		err := client.Get(ctx, gwRef.NamespacedName, gw)
		if err != nil {
			tlog.Logf(t, "error fetching Gateway: %v", err)
			return false, fmt.Errorf("error fetching Gateway: %w", err)
		}

		if err := ConditionsHaveLatestObservedGeneration(gw, gw.Status.Conditions); err != nil {
			tlog.Log(t, "Gateway", err)
			return false, nil
		}

		listener := gw.Spec.Listeners[0]
		if len(gwRef.listenerNames) != 0 {
			name := *gwRef.listenerNames[0]
			for _, l := range gw.Spec.Listeners {
				if l.Name == name {
					listener = l
					break
				}
			}
		}
		port = strconv.FormatInt(int64(listener.Port), 10)

		for _, address := range gw.Status.Addresses {
			if address.Type != nil && (*address.Type == gatewayv1.IPAddressType || *address.Type == v1alpha2.HostnameAddressType) {
				ipAddr = address.Value
				return true, nil
			}
		}

		return false, nil
	})
	require.NoErrorf(t, waitErr, "error waiting for Gateway to have at least one IP address in status")
	return net.JoinHostPort(ipAddr, port), waitErr
}

// GatewayListenersMustHaveConditions checks if every listener of the specified gateway has all
// the specified conditions.
func GatewayListenersMustHaveConditions(t *testing.T, client client.Client, timeoutConfig config.TimeoutConfig, gwName types.NamespacedName, conditions []metav1.Condition) {
	t.Helper()

	waitErr := wait.PollUntilContextTimeout(context.Background(), 1*time.Second, timeoutConfig.GatewayListenersMustHaveConditions, true, func(ctx context.Context) (bool, error) {
		var gw gatewayv1.Gateway
		if err := client.Get(ctx, gwName, &gw); err != nil {
			return false, fmt.Errorf("error fetching Gateway: %w", err)
		}

		for _, condition := range conditions {
			for _, listener := range gw.Status.Listeners {
				if !findConditionInList(t, listener.Conditions, condition.Type, string(condition.Status), condition.Reason) {
					tlog.Logf(t, "gateway %s doesn't have %s condition set to %s on %s listener", gwName, condition.Type, condition.Status, listener.Name)
					return false, nil
				}
			}
		}

		return true, nil
	})

	require.NoErrorf(t, waitErr, "error waiting for Gateway status to have conditions matching expectations on all listeners")
}

// GatewayMustHaveZeroRoutes validates that the gateway has zero routes attached.  The status
// may indicate a single listener with zero attached routes or no listeners.
func GatewayMustHaveZeroRoutes(t *testing.T, client client.Client, timeoutConfig config.TimeoutConfig, gwName types.NamespacedName) {
	var gotStatus *gatewayv1.GatewayStatus

	waitErr := wait.PollUntilContextTimeout(context.Background(), 1*time.Second, timeoutConfig.GatewayStatusMustHaveListeners, true, func(ctx context.Context) (bool, error) {
		gw := &gatewayv1.Gateway{}

		err := client.Get(ctx, gwName, gw)
		require.NoError(t, err, "error fetching Gateway")

		if err := ConditionsHaveLatestObservedGeneration(gw, gw.Status.Conditions); err != nil {
			tlog.Log(t, "Gateway ", err)
			return false, nil
		}

		// There are two valid ways to represent this:
		// 1. No listeners in status
		// 2. One listener in status with 0 attached routes
		if len(gw.Status.Listeners) == 0 {
			// No listeners in status.
			return true, nil
		}
		if len(gw.Status.Listeners) == 1 && gw.Status.Listeners[0].AttachedRoutes == 0 {
			// One listener with zero attached routes.
			return true, nil
		}
		gotStatus = &gw.Status
		return false, nil
	})
	if waitErr != nil {
		tlog.Errorf(t, "Error waiting for gateway, got Gateway Status %v, want zero listeners or exactly 1 listener with zero routes", gotStatus)
	}
}

// HTTPRouteMustHaveNoAcceptedParents waits for the specified HTTPRoute to have either no parents
// or a single parent that is not accepted. This is used to validate HTTPRoute errors.
func HTTPRouteMustHaveNoAcceptedParents(t *testing.T, client client.Client, timeoutConfig config.TimeoutConfig, routeName types.NamespacedName) {
	t.Helper()

	var actual []gatewayv1.RouteParentStatus
	emptyChecked := false
	waitErr := wait.PollUntilContextTimeout(context.Background(), 1*time.Second, timeoutConfig.HTTPRouteMustNotHaveParents, true, func(ctx context.Context) (bool, error) {
		route := &gatewayv1.HTTPRoute{}
		err := client.Get(ctx, routeName, route)
		if err != nil {
			return false, fmt.Errorf("error fetching HTTPRoute: %w", err)
		}

		actual = route.Status.Parents

		if len(actual) == 0 {
			// For empty status, we need to distinguish between "correctly did not set" and "hasn't set yet"
			// Ensure we iterate at least two times (taking advantage of the 1s poll delay) to give it some time.
			if !emptyChecked {
				emptyChecked = true
				return false, nil
			}
			return true, nil
		}
		if len(actual) > 1 {
			// Only expect one parent
			return false, nil
		}

		for _, parent := range actual {
			if err := ConditionsHaveLatestObservedGeneration(route, parent.Conditions); err != nil {
				tlog.Logf(t, "HTTPRoute %s (controller=%v,ref=%#v) %v", routeName, parent.ControllerName, parent, err)
				return false, nil
			}
		}

		return conditionsMatch(t, []metav1.Condition{{
			Type:   string(gatewayv1.RouteConditionAccepted),
			Status: "False",
		}}, actual[0].Conditions), nil
	})
	require.NoErrorf(t, waitErr, "error waiting for HTTPRoute to have no accepted parents")
}

// RouteTypeMustHaveParentsField ensures the provided routeType has a
// routeType.Status.Parents field of type []v1alpha2.RouteParentStatus.
func RouteTypeMustHaveParentsField(t *testing.T, routeType any) string {
	t.Helper()
	routeTypePointerObj := reflect.TypeOf(routeType)
	require.Equal(t, reflect.Pointer, routeTypePointerObj.Kind())

	routeTypeObj := routeTypePointerObj.Elem()
	routeTypeName := routeTypeObj.Name()

	statusField, ok := routeTypeObj.FieldByName("Status")
	require.True(t, ok, "%s does not have a Status field", routeTypeName)

	parentsField, ok := statusField.Type.FieldByName("Parents")
	require.True(t, ok, "%s.Status does not have a Parents field", routeTypeName)
	require.Equal(t, parentsField.Type, reflect.TypeOf([]v1alpha2.RouteParentStatus{}))

	return routeTypeName
}

func RouteMustHaveParents(t *testing.T, cli client.Client, timeoutConfig config.TimeoutConfig, routeName types.NamespacedName, parents []gatewayv1.RouteParentStatus, namespaceRequired bool, routeType any) {
	t.Helper()

	routeTypeName := RouteTypeMustHaveParentsField(t, routeType)

	cliObj, ok := routeType.(client.Object)
	require.True(t, ok, "error converting %v to client.Object", routeType)

	metaObj, ok := routeType.(metav1.Object)
	require.True(t, ok, "error converting %v to metav1.Object", routeType)

	var actual []gatewayv1.RouteParentStatus
	waitErr := wait.PollUntilContextTimeout(context.Background(), 1*time.Second, timeoutConfig.RouteMustHaveParents, true, func(ctx context.Context) (bool, error) {
		err := cli.Get(ctx, routeName, cliObj)
		if err != nil {
			return false, fmt.Errorf("error fetching %s: %w", routeTypeName, err)
		}

		for _, parent := range actual {
			if err := ConditionsHaveLatestObservedGeneration(metaObj, parent.Conditions); err != nil {
				tlog.Logf(t, "%s(controller=%v,ref=%#v) %v", routeTypeName, parent.ControllerName, parent, err)
				return false, nil
			}
		}

		actual = reflect.ValueOf(cliObj).Elem().FieldByName("Status").FieldByName("Parents").Interface().([]v1alpha2.RouteParentStatus)
		return parentsForRouteMatch(t, routeName, parents, actual, namespaceRequired), nil
	})
	require.NoErrorf(t, waitErr, "error waiting for %s to have parents matching expectations", routeTypeName)
}

// HTTPRouteMustHaveParents waits for the specified HTTPRoute to have parents
// in status that match the expected parents. This will cause the test to halt
// if the specified timeout is exceeded.
func HTTPRouteMustHaveParents(t *testing.T, client client.Client, timeoutConfig config.TimeoutConfig, routeName types.NamespacedName, parents []gatewayv1.RouteParentStatus, namespaceRequired bool) {
	RouteMustHaveParents(t, client, timeoutConfig, routeName, parents, namespaceRequired, &gatewayv1.HTTPRoute{})
}

// UDPRouteMustHaveParents waits for the specified UDPRoute to have parents
// in status that match the expected parents. This will cause the test to halt
// if the specified timeout is exceeded.
func UDPRouteMustHaveParents(t *testing.T, client client.Client, timeoutConfig config.TimeoutConfig, routeName types.NamespacedName, parents []gatewayv1.RouteParentStatus, namespaceRequired bool) {
	RouteMustHaveParents(t, client, timeoutConfig, routeName, parents, namespaceRequired, &v1alpha2.UDPRoute{})
}

// TLSRouteMustHaveParents waits for the specified TLSRoute to have parents
// in status that match the expected parents, and also returns the TLSRoute.
// This will cause the test to halt if the specified timeout is exceeded.
func TLSRouteMustHaveParents(t *testing.T, client client.Client, timeoutConfig config.TimeoutConfig, routeName types.NamespacedName, parents []v1alpha2.RouteParentStatus, namespaceRequired bool) v1alpha2.TLSRoute {
	t.Helper()

	var actual []gatewayv1.RouteParentStatus
	var route v1alpha2.TLSRoute

	waitErr := wait.PollUntilContextTimeout(context.Background(), 1*time.Second, timeoutConfig.RouteMustHaveParents, true, func(ctx context.Context) (bool, error) {
		err := client.Get(ctx, routeName, &route)
		if err != nil {
			return false, fmt.Errorf("error fetching TLSRoute: %w", err)
		}
		actual = route.Status.Parents
		match := parentsForRouteMatch(t, routeName, parents, actual, namespaceRequired)

		return match, nil
	})
	require.NoErrorf(t, waitErr, "error waiting for TLSRoute to have parents matching expectations")

	return route
}

func parentsForRouteMatch(t *testing.T, routeName types.NamespacedName, expected, actual []gatewayv1.RouteParentStatus, namespaceRequired bool) bool {
	t.Helper()

	if len(expected) != len(actual) {
		tlog.Logf(t, "Route %s expected %d Parents got %d", routeName, len(expected), len(actual))
		return false
	}

	// TODO(robscott): Allow for arbitrarily ordered parents
	for i, eParent := range expected {
		aParent := actual[i]
		if aParent.ControllerName != eParent.ControllerName {
			tlog.Logf(t, "Route %s ControllerName doesn't match", routeName)
			return false
		}
		if !reflect.DeepEqual(aParent.ParentRef.Group, eParent.ParentRef.Group) {
			tlog.Logf(t, "Route %s expected ParentReference.Group to be %v, got %v", routeName, eParent.ParentRef.Group, aParent.ParentRef.Group)
			return false
		}
		if !reflect.DeepEqual(aParent.ParentRef.Kind, eParent.ParentRef.Kind) {
			tlog.Logf(t, "Route %s expected ParentReference.Kind to be %v, got %v", routeName, eParent.ParentRef.Kind, aParent.ParentRef.Kind)
			return false
		}
		if aParent.ParentRef.Name != eParent.ParentRef.Name {
			tlog.Logf(t, "Route %s ParentReference.Name doesn't match", routeName)
			return false
		}
		if !reflect.DeepEqual(aParent.ParentRef.Namespace, eParent.ParentRef.Namespace) {
			if namespaceRequired || aParent.ParentRef.Namespace != nil {
				tlog.Logf(t, "Route %s expected ParentReference.Namespace to be %v, got %v", routeName, eParent.ParentRef.Namespace, aParent.ParentRef.Namespace)
				return false
			}
		}
		if !conditionsMatch(t, eParent.Conditions, aParent.Conditions) {
			return false
		}
	}

	tlog.Logf(t, "Route %s Parents matched expectations", routeName)
	return true
}

// GatewayStatusMustHaveListeners waits for the specified Gateway to have listeners
// in status that match the expected listeners. This will cause the test to halt
// if the specified timeout is exceeded.
func GatewayStatusMustHaveListeners(t *testing.T, cl client.Client, timeoutConfig config.TimeoutConfig, gwNN types.NamespacedName, listeners []gatewayv1.ListenerStatus) {
	t.Helper()

	var actual []gatewayv1.ListenerStatus
	waitErr := wait.PollUntilContextTimeout(context.Background(), 1*time.Second, timeoutConfig.GatewayStatusMustHaveListeners, true, func(ctx context.Context) (bool, error) {
		gw := &gatewayv1.Gateway{}
		err := cl.Get(ctx, gwNN, gw)
		if err != nil {
			return false, fmt.Errorf("error fetching Gateway: %w", err)
		}

		if err := ConditionsHaveLatestObservedGeneration(gw, gw.Status.Conditions); err != nil {
			tlog.Logf(t, "Gateway %s %v", client.ObjectKeyFromObject(gw), err)
			return false, nil
		}

		actual = gw.Status.Listeners
		return listenersMatch(t, listeners, actual), nil
	})
	require.NoErrorf(t, waitErr, "error waiting for Gateway status to have listeners matching expectations")
}

// HTTPRouteMustHaveCondition checks that the supplied HTTPRoute has the supplied Condition,
// halting after the specified timeout is exceeded.
func HTTPRouteMustHaveCondition(t *testing.T, client client.Client, timeoutConfig config.TimeoutConfig, routeNN types.NamespacedName, gwNN types.NamespacedName, condition metav1.Condition) {
	t.Helper()

	waitErr := wait.PollUntilContextTimeout(context.Background(), 1*time.Second, timeoutConfig.HTTPRouteMustHaveCondition, true, func(ctx context.Context) (bool, error) {
		route := &gatewayv1.HTTPRoute{}
		err := client.Get(ctx, routeNN, route)
		if err != nil {
			return false, fmt.Errorf("error fetching HTTPRoute: %w", err)
		}

		parents := route.Status.Parents
		var conditionFound bool
		for _, parent := range parents {
			if err := ConditionsHaveLatestObservedGeneration(route, parent.Conditions); err != nil {
				tlog.Logf(t, "HTTPRoute %s (parentRef=%v) %v",
					routeNN, parentRefToString(parent.ParentRef), err,
				)
				return false, nil
			}

			if parent.ParentRef.Name == gatewayv1.ObjectName(gwNN.Name) && (parent.ParentRef.Namespace == nil || string(*parent.ParentRef.Namespace) == gwNN.Namespace) {
				if findConditionInList(t, parent.Conditions, condition.Type, string(condition.Status), condition.Reason) {
					conditionFound = true
				}
			}
		}

		return conditionFound, nil
	})

	require.NoErrorf(t, waitErr, "error waiting for HTTPRoute status to have a Condition matching expectations")
}

// HTTPRouteMustHaveResolvedRefsConditionsTrue checks that the supplied HTTPRoute has the resolvedRefsCondition
// set to true.
func HTTPRouteMustHaveResolvedRefsConditionsTrue(t *testing.T, client client.Client, timeoutConfig config.TimeoutConfig, routeNN types.NamespacedName, gwNN types.NamespacedName) {
	HTTPRouteMustHaveCondition(t, client, timeoutConfig, routeNN, gwNN, metav1.Condition{
		Type:   string(gatewayv1.RouteConditionResolvedRefs),
		Status: metav1.ConditionTrue,
		Reason: string(gatewayv1.RouteReasonResolvedRefs),
	})
}

func parentRefToString(p gatewayv1.ParentReference) string {
	if p.Namespace != nil && *p.Namespace != "" {
		return fmt.Sprintf("%v/%v", p.Namespace, p.Name)
	}
	return string(p.Name)
}

// GatewayAndTLSRoutesMustBeAccepted waits until the specified Gateway has an IP
// address assigned to it and the TLSRoute has a ParentRef referring to the
// Gateway. The test will fail if these conditions are not met before the
// timeouts.
func GatewayAndTLSRoutesMustBeAccepted(t *testing.T, c client.Client, timeoutConfig config.TimeoutConfig, controllerName string, gw GatewayRef, routeNNs ...types.NamespacedName) (string, []gatewayv1.Hostname) {
	t.Helper()

	var hostnames []gatewayv1.Hostname

	gwAddr, err := WaitForGatewayAddress(t, c, timeoutConfig, gw)
	require.NoErrorf(t, err, "timed out waiting for Gateway address to be assigned")

	ns := gatewayv1.Namespace(gw.Namespace)
	kind := gatewayv1.Kind("Gateway")

	for _, routeNN := range routeNNs {
		namespaceRequired := true
		if routeNN.Namespace == gw.Namespace {
			namespaceRequired = false
		}

		var parents []gatewayv1.RouteParentStatus
		for _, listener := range gw.listenerNames {
			parents = append(parents, gatewayv1.RouteParentStatus{
				ParentRef: gatewayv1.ParentReference{
					Group:       (*gatewayv1.Group)(&gatewayv1.GroupVersion.Group),
					Kind:        &kind,
					Name:        gatewayv1.ObjectName(gw.Name),
					Namespace:   &ns,
					SectionName: listener,
				},
				ControllerName: gatewayv1.GatewayController(controllerName),
				Conditions: []metav1.Condition{
					{
						Type:   string(gatewayv1.RouteConditionAccepted),
						Status: metav1.ConditionTrue,
						Reason: string(gatewayv1.RouteReasonAccepted),
					},
				},
			})
		}
		route := TLSRouteMustHaveParents(t, c, timeoutConfig, routeNN, parents, namespaceRequired)
		hostnames = route.Spec.Hostnames
	}

	return gwAddr, hostnames
}

// TLSRouteMustHaveCondition checks that the supplied TLSRoute has the supplied Condition,
// halting after the specified timeout is exceeded.
func TLSRouteMustHaveCondition(t *testing.T, client client.Client, timeoutConfig config.TimeoutConfig, routeNN types.NamespacedName, gwNN types.NamespacedName, condition metav1.Condition) {
	t.Helper()

	waitErr := wait.PollUntilContextTimeout(context.Background(), 1*time.Second, timeoutConfig.TLSRouteMustHaveCondition, true, func(ctx context.Context) (bool, error) {
		route := &v1alpha2.TLSRoute{}
		err := client.Get(ctx, routeNN, route)
		if err != nil {
			return false, fmt.Errorf("error fetching TLSRoute: %w", err)
		}

		parents := route.Status.Parents
		var conditionFound bool
		for _, parent := range parents {
			if err := ConditionsHaveLatestObservedGeneration(route, parent.Conditions); err != nil {
				tlog.Logf(t, "TLSRoute %s (parentRef=%v) %v",
					routeNN, parentRefToString(parent.ParentRef), err,
				)
				return false, nil
			}

			if parent.ParentRef.Name == gatewayv1.ObjectName(gwNN.Name) && (parent.ParentRef.Namespace == nil || string(*parent.ParentRef.Namespace) == gwNN.Namespace) {
				if findConditionInList(t, parent.Conditions, condition.Type, string(condition.Status), condition.Reason) {
					conditionFound = true
				}
			}
		}

		return conditionFound, nil
	})

	require.NoErrorf(t, waitErr, "error waiting for TLSRoute status to have a Condition matching expectations")
}

// TODO(mikemorris): this and parentsMatch could possibly be rewritten as a generic function?
func listenersMatch(t *testing.T, expected, actual []gatewayv1.ListenerStatus) bool {
	t.Helper()

	if len(expected) != len(actual) {
		tlog.Logf(t, "Expected %d Gateway status listeners, got %d", len(expected), len(actual))
		return false
	}

	for _, eListener := range expected {
		var aListener *gatewayv1.ListenerStatus
		for i := range actual {
			if actual[i].Name == eListener.Name {
				aListener = &actual[i]
				break
			}
		}
		if aListener == nil {
			tlog.Logf(t, "Expected status for listener %s to be present", eListener.Name)
			return false
		}

		if len(eListener.SupportedKinds) == 0 && len(aListener.SupportedKinds) != 0 {
			tlog.Logf(t, "Expected list of SupportedKinds was empty, but the actual list for comparison was not:  %v",
				aListener.SupportedKinds)
			return false
		}
		// Ensure that the expected Listener.SupportedKinds items are present in actual Listener.SupportedKinds
		// Find the items instead of performing an exact match of the slice because the implementation
		// might support more Kinds than defined in the test
		for _, eKind := range eListener.SupportedKinds {
			found := false

			for _, aKind := range aListener.SupportedKinds {
				if eKind.Group == nil {
					eKind.Group = (*gatewayv1.Group)(&gatewayv1.GroupVersion.Group)
				}

				if aKind.Group == nil {
					aKind.Group = (*gatewayv1.Group)(&gatewayv1.GroupVersion.Group)
				}

				if *eKind.Group == *aKind.Group && eKind.Kind == aKind.Kind {
					found = true
					break
				}
			}
			if !found {
				tlog.Logf(t, "Expected Group:%s Kind:%s to be present in SupportedKinds", *eKind.Group, eKind.Kind)
				return false
			}
		}

		if aListener.AttachedRoutes != eListener.AttachedRoutes {
			tlog.Logf(t, "Expected AttachedRoutes to be %v, got %v", eListener.AttachedRoutes, aListener.AttachedRoutes)
			return false
		}
		if !conditionsMatch(t, eListener.Conditions, aListener.Conditions) {
			tlog.Logf(t, "Expected Conditions to be %v, got %v", eListener.Conditions, aListener.Conditions)
			return false
		}
	}

	tlog.Logf(t, "Gateway status listeners matched expectations")
	return true
}

func conditionsMatch(t *testing.T, expected, actual []metav1.Condition) bool {
	t.Helper()

	if len(actual) < len(expected) {
		tlog.Logf(t, "Expected more conditions to be present")
		return false
	}
	for _, condition := range expected {
		if !findConditionInList(t, actual, condition.Type, string(condition.Status), condition.Reason) {
			return false
		}
	}

	tlog.Logf(t, "Conditions matched expectations")
	return true
}

// findConditionInList finds a condition in a list of Conditions, checking
// the Name, Value, and Reason. If an empty reason is passed, any Reason will match.
// If an empty status is passed, any Status will match.
func findConditionInList(t *testing.T, conditions []metav1.Condition, condName, expectedStatus, expectedReason string) bool {
	t.Helper()

	for _, cond := range conditions {
		if cond.Type == condName {
			// an empty Status string means "Match any status".
			if expectedStatus == "" || cond.Status == metav1.ConditionStatus(expectedStatus) {
				// an empty Reason string means "Match any reason".
				if expectedReason == "" || cond.Reason == expectedReason {
					return true
				}
				tlog.Logf(t, "%s condition Reason set to %s, expected %s", condName, cond.Reason, expectedReason)
			}

			tlog.Logf(t, "%s condition set to Status %s with Reason %v, expected Status %s", condName, cond.Status, cond.Reason, expectedStatus)
		}
	}

	tlog.Logf(t, "%s was not in conditions list [%v]", condName, conditions)
	return false
}

func findPodConditionInList(t *testing.T, conditions []v1.PodCondition, condName, condValue string) bool {
	t.Helper()

	for _, cond := range conditions {
		if cond.Type == v1.PodConditionType(condName) {
			if cond.Status == v1.ConditionStatus(condValue) {
				return true
			}
			tlog.Logf(t, "%s condition set to %s, expected %s", condName, cond.Status, condValue)
		}
	}

	tlog.Logf(t, "%s was not in conditions list", condName)
	return false
}
