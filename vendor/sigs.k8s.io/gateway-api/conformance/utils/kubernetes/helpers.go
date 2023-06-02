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

	"sigs.k8s.io/gateway-api/apis/v1alpha2"
	"sigs.k8s.io/gateway-api/apis/v1beta1"
	"sigs.k8s.io/gateway-api/conformance/utils/config"
)

// GatewayRef is a tiny type for specifying an HTTP Route ParentRef without
// relying on a specific api version.
type GatewayRef struct {
	types.NamespacedName
	listenerNames []*v1beta1.SectionName
}

// NewGatewayRef creates a GatewayRef resource.  ListenerNames are optional.
func NewGatewayRef(nn types.NamespacedName, listenerNames ...string) GatewayRef {
	var listeners []*v1beta1.SectionName

	if len(listenerNames) == 0 {
		listenerNames = append(listenerNames, "")
	}

	for _, listener := range listenerNames {
		sectionName := v1beta1.SectionName(listener)
		listeners = append(listeners, &sectionName)
	}
	return GatewayRef{
		NamespacedName: nn,
		listenerNames:  listeners,
	}
}

// GWCMustBeAcceptedConditionTrue waits until the specified GatewayClass has an Accepted condition set with a status value equal to True.
func GWCMustHaveAcceptedConditionTrue(t *testing.T, c client.Client, timeoutConfig config.TimeoutConfig, gwcName string) string {
	return gwcMustBeAccepted(t, c, timeoutConfig, gwcName, string(metav1.ConditionTrue))
}

// GWCMustBeAcceptedConditionAny waits until the specified GatewayClass has an Accepted condition set with a status set to any value.
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
	waitErr := wait.PollImmediate(1*time.Second, timeoutConfig.GWCMustBeAccepted, func() (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		gwc := &v1beta1.GatewayClass{}
		err := c.Get(ctx, types.NamespacedName{Name: gwcName}, gwc)
		if err != nil {
			return false, fmt.Errorf("error fetching GatewayClass: %w", err)
		}

		controllerName = string(gwc.Spec.ControllerName)

		if err := ConditionsHaveLatestObservedGeneration(gwc, gwc.Status.Conditions); err != nil {
			t.Log("GatewayClass", err)
			return false, nil
		}

		// Passing an empty string as the Reason means that any Reason will do.
		return findConditionInList(t, gwc.Status.Conditions, "Accepted", expectedStatus, ""), nil
	})
	require.NoErrorf(t, waitErr, "error waiting for %s GatewayClass to have Accepted condition to be set: %v", gwcName, waitErr)

	return controllerName
}

// GatewayMustHaveLatestConditions will fail the test if there are
// conditions that were not updated
func GatewayMustHaveLatestConditions(t *testing.T, gw *v1beta1.Gateway) {
	t.Helper()

	if err := ConditionsHaveLatestObservedGeneration(gw, gw.Status.Conditions); err != nil {
		t.Fatalf("Gateway %v", err)
	}
}

// GatewayClassMustHaveLatestConditions will fail the test if there are
// conditions that were not updated
func GatewayClassMustHaveLatestConditions(t *testing.T, gwc *v1beta1.GatewayClass) {
	t.Helper()

	if err := ConditionsHaveLatestObservedGeneration(gwc, gwc.Status.Conditions); err != nil {
		t.Fatalf("GatewayClass %v", err)
	}
}

// HTTPRouteMustHaveLatestConditions will fail the test if there are
// conditions that were not updated
func HTTPRouteMustHaveLatestConditions(t *testing.T, r *v1beta1.HTTPRoute) {
	t.Helper()

	for _, parent := range r.Status.Parents {
		if err := ConditionsHaveLatestObservedGeneration(r, parent.Conditions); err != nil {
			t.Fatalf("HTTPRoute(controller=%v, parentRef=%#v) %v", parent.ControllerName, parent, err)
		}
	}
}

func ConditionsHaveLatestObservedGeneration(obj metav1.Object, conditions []metav1.Condition) error {
	staleConditions := FilterStaleConditions(obj, conditions)

	if len(staleConditions) == 0 {
		return nil
	}

	var b strings.Builder
	fmt.Fprint(&b, "expected observedGeneration to be updated for all conditions")
	fmt.Fprintf(&b, ", only %d/%d were updated.", len(conditions)-len(staleConditions), len(conditions))
	fmt.Fprintf(&b, " stale conditions are: ")

	for i, c := range staleConditions {
		fmt.Fprintf(&b, c.Type)
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

// NamespacesMustBeAccepted waits until all Pods are marked ready and all Gateways
// are marked accepted in the provided namespaces. This will cause the test to
// halt if the specified timeout is exceeded.
func NamespacesMustBeAccepted(t *testing.T, c client.Client, timeoutConfig config.TimeoutConfig, namespaces []string) {
	t.Helper()

	waitErr := wait.PollImmediate(1*time.Second, timeoutConfig.NamespacesMustBeReady, func() (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		for _, ns := range namespaces {
			gwList := &v1beta1.GatewayList{}
			err := c.List(ctx, gwList, client.InNamespace(ns))
			if err != nil {
				t.Errorf("Error listing Gateways: %v", err)
			}
			for _, gw := range gwList.Items {
				gw := gw

				if err = ConditionsHaveLatestObservedGeneration(&gw, gw.Status.Conditions); err != nil {
					t.Log(err)
					return false, nil
				}

				// Passing an empty string as the Reason means that any Reason will do.
				if !findConditionInList(t, gw.Status.Conditions, string(v1beta1.GatewayConditionAccepted), "True", "") {
					t.Logf("%s/%s Gateway not ready yet", ns, gw.Name)
					return false, nil
				}
			}

			podList := &v1.PodList{}
			err = c.List(ctx, podList, client.InNamespace(ns))
			if err != nil {
				t.Errorf("Error listing Pods: %v", err)
			}
			for _, pod := range podList.Items {
				if !findPodConditionInList(t, pod.Status.Conditions, "Ready", "True") &&
					pod.Status.Phase != v1.PodSucceeded {
					t.Logf("%s/%s Pod not ready yet", ns, pod.Name)
					return false, nil
				}
			}
		}
		t.Logf("Gateways and Pods in %s namespaces ready", strings.Join(namespaces, ", "))
		return true, nil
	})
	require.NoErrorf(t, waitErr, "error waiting for %s namespaces to be ready", strings.Join(namespaces, ", "))
}

// GatewayAndHTTPRoutesMustBeAccepted waits until the specified Gateway has an IP
// address assigned to it and the Route has a ParentRef referring to the
// Gateway. The test will fail if these conditions are not met before the
// timeouts.
func GatewayAndHTTPRoutesMustBeAccepted(t *testing.T, c client.Client, timeoutConfig config.TimeoutConfig, controllerName string, gw GatewayRef, routeNNs ...types.NamespacedName) string {
	t.Helper()

	gwAddr, err := WaitForGatewayAddress(t, c, timeoutConfig, gw.NamespacedName)
	require.NoErrorf(t, err, "timed out waiting for Gateway address to be assigned")

	ns := v1beta1.Namespace(gw.Namespace)
	kind := v1beta1.Kind("Gateway")

	for _, routeNN := range routeNNs {
		namespaceRequired := true
		if routeNN.Namespace == gw.Namespace {
			namespaceRequired = false
		}

		var parents []v1beta1.RouteParentStatus
		for _, listener := range gw.listenerNames {
			parents = append(parents, v1beta1.RouteParentStatus{
				ParentRef: v1beta1.ParentReference{
					Group:       (*v1beta1.Group)(&v1beta1.GroupVersion.Group),
					Kind:        &kind,
					Name:        v1beta1.ObjectName(gw.Name),
					Namespace:   &ns,
					SectionName: listener,
				},
				ControllerName: v1beta1.GatewayController(controllerName),
				Conditions: []metav1.Condition{
					{
						Type:   string(v1beta1.RouteConditionAccepted),
						Status: metav1.ConditionTrue,
						Reason: string(v1beta1.RouteReasonAccepted),
					},
				},
			})
		}
		HTTPRouteMustHaveParents(t, c, timeoutConfig, routeNN, parents, namespaceRequired)
	}

	return gwAddr
}

// WaitForGatewayAddress waits until at least one IP Address has been set in the
// status of the specified Gateway.
func WaitForGatewayAddress(t *testing.T, client client.Client, timeoutConfig config.TimeoutConfig, gwName types.NamespacedName) (string, error) {
	t.Helper()

	var ipAddr, port string
	waitErr := wait.PollImmediate(1*time.Second, timeoutConfig.GatewayMustHaveAddress, func() (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		gw := &v1beta1.Gateway{}
		err := client.Get(ctx, gwName, gw)
		if err != nil {
			t.Logf("error fetching Gateway: %v", err)
			return false, fmt.Errorf("error fetching Gateway: %w", err)
		}

		if err := ConditionsHaveLatestObservedGeneration(gw, gw.Status.Conditions); err != nil {
			t.Log("Gateway", err)
			return false, nil
		}

		port = strconv.FormatInt(int64(gw.Spec.Listeners[0].Port), 10)

		// TODO: Support more than IPAddress
		for _, address := range gw.Status.Addresses {
			if address.Type != nil && *address.Type == v1beta1.IPAddressType {
				ipAddr = address.Value
				return true, nil
			}
		}

		return false, nil
	})
	require.NoErrorf(t, waitErr, "error waiting for Gateway to have at least one IP address in status")
	return net.JoinHostPort(ipAddr, port), waitErr
}

// GatewayMustHaveZeroRoutes validates that the gateway has zero routes attached.  The status
// may indicate a single listener with zero attached routes or no listeners.
func GatewayMustHaveZeroRoutes(t *testing.T, client client.Client, timeoutConfig config.TimeoutConfig, gwName types.NamespacedName) {
	var gotStatus *v1beta1.GatewayStatus
	waitErr := wait.PollImmediate(1*time.Second, timeoutConfig.GatewayStatusMustHaveListeners, func() (bool, error) {
		gw := &v1beta1.Gateway{}
		ctx, cancel := context.WithTimeout(context.Background(), timeoutConfig.GetTimeout)
		defer cancel()
		err := client.Get(ctx, gwName, gw)
		require.NoError(t, err, "error fetching Gateway")

		if err := ConditionsHaveLatestObservedGeneration(gw, gw.Status.Conditions); err != nil {
			t.Log("Gateway ", err)
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
		t.Errorf("Error waiting for gateway, got Gateway Status %v, want zero listeners or exactly 1 listener with zero routes", gotStatus)
	}
}

// HTTPRouteMustHaveNoAcceptedParents waits for the specified HTTPRoute to have either no parents
// or a single parent that is not accepted. This is used to validate HTTPRoute errors.
func HTTPRouteMustHaveNoAcceptedParents(t *testing.T, client client.Client, timeoutConfig config.TimeoutConfig, routeName types.NamespacedName) {
	t.Helper()

	var actual []v1beta1.RouteParentStatus
	emptyChecked := false
	waitErr := wait.PollImmediate(1*time.Second, timeoutConfig.HTTPRouteMustNotHaveParents, func() (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		route := &v1beta1.HTTPRoute{}
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
				t.Logf("HTTPRoute(controller=%v,ref=%#v) %v", parent.ControllerName, parent, err)
				return false, nil
			}
		}

		return conditionsMatch(t, []metav1.Condition{{
			Type:   string(v1beta1.RouteConditionAccepted),
			Status: "False",
		}}, actual[0].Conditions), nil
	})
	require.NoErrorf(t, waitErr, "error waiting for HTTPRoute to have no accepted parents")
}

// HTTPRouteMustHaveParents waits for the specified HTTPRoute to have parents
// in status that match the expected parents. This will cause the test to halt
// if the specified timeout is exceeded.
func HTTPRouteMustHaveParents(t *testing.T, client client.Client, timeoutConfig config.TimeoutConfig, routeName types.NamespacedName, parents []v1beta1.RouteParentStatus, namespaceRequired bool) {
	t.Helper()

	var actual []v1beta1.RouteParentStatus
	waitErr := wait.PollImmediate(1*time.Second, timeoutConfig.RouteMustHaveParents, func() (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		route := &v1beta1.HTTPRoute{}
		err := client.Get(ctx, routeName, route)
		if err != nil {
			return false, fmt.Errorf("error fetching HTTPRoute: %w", err)
		}

		for _, parent := range actual {
			if err := ConditionsHaveLatestObservedGeneration(route, parent.Conditions); err != nil {
				t.Logf("HTTPRoute(controller=%v,ref=%#v) %v", parent.ControllerName, parent, err)
				return false, nil
			}
		}

		actual = route.Status.Parents
		return parentsForRouteMatch(t, routeName, parents, actual, namespaceRequired), nil
	})
	require.NoErrorf(t, waitErr, "error waiting for HTTPRoute to have parents matching expectations")
}

// TLSRouteMustHaveParents waits for the specified TLSRoute to have parents
// in status that match the expected parents, and also returns the TLSRoute.
// This will cause the test to halt if the specified timeout is exceeded.
func TLSRouteMustHaveParents(t *testing.T, client client.Client, timeoutConfig config.TimeoutConfig, routeName types.NamespacedName, parents []v1alpha2.RouteParentStatus, namespaceRequired bool) v1alpha2.TLSRoute {
	t.Helper()

	var actual []v1beta1.RouteParentStatus
	var route v1alpha2.TLSRoute

	waitErr := wait.PollImmediate(1*time.Second, timeoutConfig.RouteMustHaveParents, func() (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

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

func parentsForRouteMatch(t *testing.T, routeName types.NamespacedName, expected, actual []v1beta1.RouteParentStatus, namespaceRequired bool) bool {
	t.Helper()

	if len(expected) != len(actual) {
		t.Logf("Route %s/%s expected %d Parents got %d", routeName.Namespace, routeName.Name, len(expected), len(actual))
		return false
	}

	// TODO(robscott): Allow for arbitrarily ordered parents
	for i, eParent := range expected {
		aParent := actual[i]
		if aParent.ControllerName != eParent.ControllerName {
			t.Logf("Route %s/%s ControllerName doesn't match", routeName.Namespace, routeName.Name)
			return false
		}
		if !reflect.DeepEqual(aParent.ParentRef.Group, eParent.ParentRef.Group) {

			t.Logf("Route %s/%s expected ParentReference.Group to be %v, got %v", routeName.Namespace, routeName.Name, eParent.ParentRef.Group, aParent.ParentRef.Group)
			return false
		}
		if !reflect.DeepEqual(aParent.ParentRef.Kind, eParent.ParentRef.Kind) {
			t.Logf("Route %s/%s expected ParentReference.Kind to be %v, got %v", routeName.Namespace, routeName.Name, eParent.ParentRef.Kind, aParent.ParentRef.Kind)
			return false
		}
		if aParent.ParentRef.Name != eParent.ParentRef.Name {
			t.Logf("Route %s/%s ParentReference.Name doesn't match", routeName.Namespace, routeName.Name)
			return false
		}
		if !reflect.DeepEqual(aParent.ParentRef.Namespace, eParent.ParentRef.Namespace) {
			if namespaceRequired || aParent.ParentRef.Namespace != nil {
				t.Logf("Route %s/%s expected ParentReference.Namespace to be %v, got %v", routeName.Namespace, routeName.Name, eParent.ParentRef.Namespace, aParent.ParentRef.Namespace)
				return false
			}
		}
		if !conditionsMatch(t, eParent.Conditions, aParent.Conditions) {
			return false
		}
	}

	t.Logf("Route %s/%s Parents matched expectations", routeName.Namespace, routeName.Name)
	return true
}

// GatewayStatusMustHaveListeners waits for the specified Gateway to have listeners
// in status that match the expected listeners. This will cause the test to halt
// if the specified timeout is exceeded.
func GatewayStatusMustHaveListeners(t *testing.T, client client.Client, timeoutConfig config.TimeoutConfig, gwNN types.NamespacedName, listeners []v1beta1.ListenerStatus) {
	t.Helper()

	var actual []v1beta1.ListenerStatus
	waitErr := wait.PollImmediate(1*time.Second, timeoutConfig.GatewayStatusMustHaveListeners, func() (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		gw := &v1beta1.Gateway{}
		err := client.Get(ctx, gwNN, gw)
		if err != nil {
			return false, fmt.Errorf("error fetching Gateway: %w", err)
		}

		if err := ConditionsHaveLatestObservedGeneration(gw, gw.Status.Conditions); err != nil {
			t.Log("Gateway", err)
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

	waitErr := wait.PollImmediate(1*time.Second, timeoutConfig.HTTPRouteMustHaveCondition, func() (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		route := &v1beta1.HTTPRoute{}
		err := client.Get(ctx, routeNN, route)
		if err != nil {
			return false, fmt.Errorf("error fetching HTTPRoute: %w", err)
		}

		parents := route.Status.Parents
		var conditionFound bool
		for _, parent := range parents {
			if err := ConditionsHaveLatestObservedGeneration(route, parent.Conditions); err != nil {

				t.Logf("HTTPRoute(parentRef=%v) %v", parentRefToString(parent.ParentRef), err)
				return false, nil
			}

			if parent.ParentRef.Name == v1beta1.ObjectName(gwNN.Name) && (parent.ParentRef.Namespace == nil || string(*parent.ParentRef.Namespace) == gwNN.Namespace) {
				if findConditionInList(t, parent.Conditions, condition.Type, string(condition.Status), condition.Reason) {
					conditionFound = true
				}
			}
		}

		return conditionFound, nil
	})

	require.NoErrorf(t, waitErr, "error waiting for HTTPRoute status to have a Condition matching expectations")
}

func parentRefToString(p v1beta1.ParentReference) string {
	if p.Namespace != nil && *p.Namespace != "" {
		return fmt.Sprintf("%v/%v", p.Namespace, p.Name)
	}
	return string(p.Name)
}

// GatewayAndTLSRoutesMustBeAccepted waits until the specified Gateway has an IP
// address assigned to it and the TLSRoute has a ParentRef referring to the
// Gateway. The test will fail if these conditions are not met before the
// timeouts.
func GatewayAndTLSRoutesMustBeAccepted(t *testing.T, c client.Client, timeoutConfig config.TimeoutConfig, controllerName string, gw GatewayRef, routeNNs ...types.NamespacedName) (string, []v1beta1.Hostname) {
	t.Helper()

	var hostnames []v1beta1.Hostname

	gwAddr, err := WaitForGatewayAddress(t, c, timeoutConfig, gw.NamespacedName)
	require.NoErrorf(t, err, "timed out waiting for Gateway address to be assigned")

	ns := v1beta1.Namespace(gw.Namespace)
	kind := v1beta1.Kind("Gateway")

	for _, routeNN := range routeNNs {
		namespaceRequired := true
		if routeNN.Namespace == gw.Namespace {
			namespaceRequired = false
		}

		var parents []v1beta1.RouteParentStatus
		for _, listener := range gw.listenerNames {
			parents = append(parents, v1beta1.RouteParentStatus{
				ParentRef: v1beta1.ParentReference{
					Group:       (*v1beta1.Group)(&v1beta1.GroupVersion.Group),
					Kind:        &kind,
					Name:        v1beta1.ObjectName(gw.Name),
					Namespace:   &ns,
					SectionName: listener,
				},
				ControllerName: v1beta1.GatewayController(controllerName),
				Conditions: []metav1.Condition{
					{
						Type:   string(v1beta1.RouteConditionAccepted),
						Status: metav1.ConditionTrue,
						Reason: string(v1beta1.RouteReasonAccepted),
					},
				},
			})
		}
		route := TLSRouteMustHaveParents(t, c, timeoutConfig, routeNN, parents, namespaceRequired)
		hostnames = route.Spec.Hostnames
	}

	return gwAddr, hostnames
}

// TODO(mikemorris): this and parentsMatch could possibly be rewritten as a generic function?
func listenersMatch(t *testing.T, expected, actual []v1beta1.ListenerStatus) bool {
	t.Helper()

	if len(expected) != len(actual) {
		t.Logf("Expected %d Gateway status listeners, got %d", len(expected), len(actual))
		return false
	}

	// TODO(mikemorris): Allow for arbitrarily ordered listeners
	for i, eListener := range expected {
		aListener := actual[i]
		if aListener.Name != eListener.Name {
			t.Logf("Name doesn't match")
			return false
		}

		if len(eListener.SupportedKinds) == 0 && len(aListener.SupportedKinds) != 0 {
			t.Logf("Expected list of SupportedKinds was empty, but the actual list for comparison was not:  %v",
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
					eKind.Group = (*v1beta1.Group)(&v1beta1.GroupVersion.Group)
				}

				if aKind.Group == nil {
					aKind.Group = (*v1beta1.Group)(&v1beta1.GroupVersion.Group)
				}

				if *eKind.Group == *aKind.Group && eKind.Kind == aKind.Kind {
					found = true
					break
				}
			}
			if !found {
				t.Logf("Expected Group:%s Kind:%s to be present in SupportedKinds", *eKind.Group, eKind.Kind)
				return false
			}
		}

		if aListener.AttachedRoutes != eListener.AttachedRoutes {
			t.Logf("Expected AttachedRoutes to be %v, got %v", eListener.AttachedRoutes, aListener.AttachedRoutes)
			return false
		}
		if !conditionsMatch(t, eListener.Conditions, aListener.Conditions) {
			t.Logf("Expected Conditions to be %v, got %v", eListener.Conditions, aListener.Conditions)
			return false
		}
	}

	t.Logf("Gateway status listeners matched expectations")
	return true
}

func conditionsMatch(t *testing.T, expected, actual []metav1.Condition) bool {
	t.Helper()

	if len(actual) < len(expected) {
		t.Logf("Expected more conditions to be present")
		return false
	}
	for _, condition := range expected {
		if !findConditionInList(t, actual, condition.Type, string(condition.Status), condition.Reason) {
			return false
		}
	}

	t.Logf("Conditions matched expectations")
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
				t.Logf("%s condition Reason set to %s, expected %s", condName, cond.Reason, expectedReason)
			}

			t.Logf("%s condition set to Status %s with Reason %v, expected Status %s", condName, cond.Status, cond.Reason, expectedStatus)
		}
	}

	t.Logf("%s was not in conditions list [%v]", condName, conditions)
	return false
}

func findPodConditionInList(t *testing.T, conditions []v1.PodCondition, condName, condValue string) bool {
	t.Helper()

	for _, cond := range conditions {
		if cond.Type == v1.PodConditionType(condName) {
			if cond.Status == v1.ConditionStatus(condValue) {
				return true
			}
			t.Logf("%s condition set to %s, expected %s", condName, cond.Status, condValue)
		}
	}

	t.Logf("%s was not in conditions list", condName)
	return false
}
