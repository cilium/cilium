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
)

// GatewayRef is a tiny type for specifying an HTTP Route ParentRef without
// relying on a specific api version.
type GatewayRef struct {
	types.NamespacedName
	listenerNames []*v1alpha2.SectionName
}

// NewGatewayRef creates a GatewayRef resource.  ListenerNames are optional.
func NewGatewayRef(nn types.NamespacedName, listenerNames ...string) GatewayRef {
	var listeners []*v1alpha2.SectionName

	if len(listenerNames) == 0 {
		listenerNames = append(listenerNames, "")
	}

	for _, listener := range listenerNames {
		sectionName := v1alpha2.SectionName(listener)
		listeners = append(listeners, &sectionName)
	}
	return GatewayRef{
		NamespacedName: nn,
		listenerNames:  listeners,
	}
}

// GWCMustBeAccepted waits until the specified GatewayClass has an Accepted
// condition set to true. It also returns the ControllerName for the
// GatewayClass. This will cause the test to halt if the specified timeout is
// exceeded.
func GWCMustBeAccepted(t *testing.T, c client.Client, gwcName string, seconds int) string {
	t.Helper()

	var controllerName string
	waitFor := time.Duration(seconds) * time.Second
	waitErr := wait.PollImmediate(1*time.Second, waitFor, func() (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		gwc := &v1alpha2.GatewayClass{}
		err := c.Get(ctx, types.NamespacedName{Name: gwcName}, gwc)
		if err != nil {
			return false, fmt.Errorf("error fetching GatewayClass: %w", err)
		}

		controllerName = string(gwc.Spec.ControllerName)
		// Passing an empty string as the Reason means that any Reason will do.
		return findConditionInList(t, gwc.Status.Conditions, "Accepted", "True", ""), nil
	})
	require.NoErrorf(t, waitErr, "error waiting for %s GatewayClass to have Accepted condition set to True: %v", gwcName, waitErr)

	return controllerName
}

// NamespacesMustBeReady waits until all Pods and Gateways in the provided
// namespaces are marked as ready. This will cause the test to halt if the
// specified timeout is exceeded.
func NamespacesMustBeReady(t *testing.T, c client.Client, namespaces []string, seconds int) {
	t.Helper()

	waitFor := time.Duration(seconds) * time.Second
	waitErr := wait.PollImmediate(1*time.Second, waitFor, func() (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		for _, ns := range namespaces {
			gwList := &v1alpha2.GatewayList{}
			err := c.List(ctx, gwList, client.InNamespace(ns))
			if err != nil {
				t.Errorf("Error listing Gateways: %v", err)
			}
			for _, gw := range gwList.Items {
				// Passing an empty string as the Reason means that any Reason will do.
				if !findConditionInList(t, gw.Status.Conditions, "Ready", "True", "") {
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

// GatewayAndHTTPRoutesMustBeReady waits until the specified Gateway has an IP
// address assigned to it and the Route has a ParentRef referring to the
// Gateway. The test will fail if these conditions are not met before the
// timeouts.
func GatewayAndHTTPRoutesMustBeReady(t *testing.T, c client.Client, controllerName string, gw GatewayRef, routeNNs ...types.NamespacedName) string {
	t.Helper()

	gwAddr, err := WaitForGatewayAddress(t, c, gw.NamespacedName, 180)
	require.NoErrorf(t, err, "timed out waiting for Gateway address to be assigned")

	ns := v1alpha2.Namespace(gw.Namespace)
	kind := v1alpha2.Kind("Gateway")

	for _, routeNN := range routeNNs {
		namespaceRequired := true
		if routeNN.Namespace == gw.Namespace {
			namespaceRequired = false
		}

		var parents []v1alpha2.RouteParentStatus
		for _, listener := range gw.listenerNames {
			parents = append(parents, v1alpha2.RouteParentStatus{
				ParentRef: v1alpha2.ParentReference{
					Group:       (*v1alpha2.Group)(&v1alpha2.GroupVersion.Group),
					Kind:        &kind,
					Name:        v1alpha2.ObjectName(gw.Name),
					Namespace:   &ns,
					SectionName: listener,
				},
				ControllerName: v1alpha2.GatewayController(controllerName),
				Conditions: []metav1.Condition{
					{
						Type:   string(v1alpha2.RouteConditionAccepted),
						Status: metav1.ConditionTrue,
						Reason: string(v1alpha2.RouteReasonAccepted),
					},
				},
			})
		}
		HTTPRouteMustHaveParents(t, c, routeNN, parents, namespaceRequired, 60)
	}

	return gwAddr
}

// WaitForGatewayAddress waits until at least one IP Address has been set in the
// status of the specified Gateway.
func WaitForGatewayAddress(t *testing.T, client client.Client, gwName types.NamespacedName, seconds int) (string, error) {
	t.Helper()

	var ipAddr, port string
	waitFor := time.Duration(seconds) * time.Second
	waitErr := wait.PollImmediate(1*time.Second, waitFor, func() (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		gw := &v1alpha2.Gateway{}
		err := client.Get(ctx, gwName, gw)
		if err != nil {
			t.Logf("error fetching Gateway: %v", err)
			return false, fmt.Errorf("error fetching Gateway: %w", err)
		}

		port = strconv.FormatInt(int64(gw.Spec.Listeners[0].Port), 10)

		// TODO: Support more than IPAddress
		for _, address := range gw.Status.Addresses {
			if address.Type != nil && *address.Type == v1alpha2.IPAddressType {
				ipAddr = address.Value
				return true, nil
			}
		}

		return false, nil
	})
	require.NoErrorf(t, waitErr, "error waiting for Gateway to have at least one IP address in status")
	return net.JoinHostPort(ipAddr, port), waitErr
}

// HTTPRouteMustHaveNoAcceptedParents waits for the specified HTTPRoute to have either no parents
// or a single parent that is not accepted. This is used to validate HTTPRoute errors.
func HTTPRouteMustHaveNoAcceptedParents(t *testing.T, client client.Client, routeName types.NamespacedName, seconds int) {
	t.Helper()

	var actual []v1alpha2.RouteParentStatus
	waitFor := time.Duration(seconds) * time.Second
	emptyChecked := false
	waitErr := wait.PollImmediate(1*time.Second, waitFor, func() (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		route := &v1alpha2.HTTPRoute{}
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
		return conditionsMatch(t, []metav1.Condition{{
			Type:   string(v1alpha2.RouteConditionAccepted),
			Status: "False",
		}}, actual[0].Conditions), nil
	})
	require.NoErrorf(t, waitErr, "error waiting for HTTPRoute to have no accepted parents")
}

// HTTPRouteMustHaveParents waits for the specified HTTPRoute to have parents
// in status that match the expected parents. This will cause the test to halt
// if the specified timeout is exceeded.
func HTTPRouteMustHaveParents(t *testing.T, client client.Client, routeName types.NamespacedName, parents []v1alpha2.RouteParentStatus, namespaceRequired bool, seconds int) {
	t.Helper()

	var actual []v1alpha2.RouteParentStatus
	waitFor := time.Duration(seconds) * time.Second
	waitErr := wait.PollImmediate(1*time.Second, waitFor, func() (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		route := &v1alpha2.HTTPRoute{}
		err := client.Get(ctx, routeName, route)
		if err != nil {
			return false, fmt.Errorf("error fetching HTTPRoute: %w", err)
		}

		actual = route.Status.Parents

		return parentsMatch(t, parents, actual, namespaceRequired), nil
	})
	require.NoErrorf(t, waitErr, "error waiting for HTTPRoute to have parents matching expectations")
}

func parentsMatch(t *testing.T, expected, actual []v1alpha2.RouteParentStatus, namespaceRequired bool) bool {
	t.Helper()

	if len(expected) != len(actual) {
		t.Logf("Expected %d Route parents, got %d", len(expected), len(actual))
		return false
	}

	// TODO(robscott): Allow for arbitrarily ordered parents
	for i, eParent := range expected {
		aParent := actual[i]
		if aParent.ControllerName != eParent.ControllerName {
			t.Logf("ControllerName doesn't match")
			return false
		}
		if !reflect.DeepEqual(aParent.ParentRef.Group, eParent.ParentRef.Group) {
			t.Logf("Expected ParentReference.Group to be %v, got %v", eParent.ParentRef.Group, aParent.ParentRef.Group)
			return false
		}
		if !reflect.DeepEqual(aParent.ParentRef.Kind, eParent.ParentRef.Kind) {
			t.Logf("Expected ParentReference.Kind to be %v, got %v", eParent.ParentRef.Kind, aParent.ParentRef.Kind)
			return false
		}
		if aParent.ParentRef.Name != eParent.ParentRef.Name {
			t.Logf("ParentReference.Name doesn't match")
			return false
		}
		if !reflect.DeepEqual(aParent.ParentRef.Namespace, eParent.ParentRef.Namespace) {
			if namespaceRequired || aParent.ParentRef.Namespace != nil {
				t.Logf("Expected ParentReference.Namespace to be %v, got %v", eParent.ParentRef.Namespace, aParent.ParentRef.Namespace)
				return false
			}
		}
		if !conditionsMatch(t, eParent.Conditions, aParent.Conditions) {
			return false
		}
	}

	t.Logf("Route parents matched expectations")
	return true
}

// GatewayStatusMustHaveListeners waits for the specified Gateway to have listeners
// in status that match the expected listeners. This will cause the test to halt
// if the specified timeout is exceeded.
func GatewayStatusMustHaveListeners(t *testing.T, client client.Client, gwNN types.NamespacedName, listeners []v1alpha2.ListenerStatus, seconds int) {
	t.Helper()

	var actual []v1alpha2.ListenerStatus
	waitFor := time.Duration(seconds) * time.Second
	waitErr := wait.PollImmediate(1*time.Second, waitFor, func() (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		gw := &v1alpha2.Gateway{}
		err := client.Get(ctx, gwNN, gw)
		if err != nil {
			return false, fmt.Errorf("error fetching Gateway: %w", err)
		}

		actual = gw.Status.Listeners

		return listenersMatch(t, listeners, actual), nil
	})
	require.NoErrorf(t, waitErr, "error waiting for Gateway status to have listeners matching expectations")
}

// HTTPRouteMustHaveConditions checks that the supplied HTTPRoute has the supplied Condition,
// halting after the specified timeout is exceeded.
func HTTPRouteMustHaveCondition(t *testing.T, client client.Client, routeNN types.NamespacedName, gwNN types.NamespacedName, condition metav1.Condition, seconds int) {
	t.Helper()

	waitFor := time.Duration(seconds) * time.Second
	waitErr := wait.PollImmediate(1*time.Second, waitFor, func() (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		route := &v1alpha2.HTTPRoute{}
		err := client.Get(ctx, routeNN, route)
		if err != nil {
			return false, fmt.Errorf("error fetching HTTPRoute: %w", err)
		}

		parents := route.Status.Parents

		var conditionFound bool
		for _, parent := range parents {
			if parent.ParentRef.Name == v1alpha2.ObjectName(gwNN.Name) && (parent.ParentRef.Namespace == nil || string(*parent.ParentRef.Namespace) == gwNN.Namespace) {
				if findConditionInList(t, parent.Conditions, condition.Type, string(condition.Status), condition.Reason) {
					conditionFound = true
				}
			}
		}

		return conditionFound, nil
	})

	require.NoErrorf(t, waitErr, "error waiting for HTTPRoute status to have a Condition matching expectations")
}

// TODO(mikemorris): this and parentsMatch could possibly be rewritten as a generic function?
func listenersMatch(t *testing.T, expected, actual []v1alpha2.ListenerStatus) bool {
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
		if !reflect.DeepEqual(aListener.SupportedKinds, eListener.SupportedKinds) {
			t.Logf("Expected SupportedKinds to be %v, got %v", eListener.SupportedKinds, aListener.SupportedKinds)
			return false
		}
		if aListener.AttachedRoutes != eListener.AttachedRoutes {
			t.Logf("Expected AttachedRoutes to be %v, got %v", eListener.AttachedRoutes, aListener.AttachedRoutes)
			return false
		}
		if !conditionsMatch(t, eListener.Conditions, aListener.Conditions) {
			return false
		}
	}

	t.Logf("Gateway status listeners matched expectations")
	return true
}

func conditionsMatch(t *testing.T, expected, actual []metav1.Condition) bool {
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
func findConditionInList(t *testing.T, conditions []metav1.Condition, condName, condValue, condReason string) bool {
	for _, cond := range conditions {
		if cond.Type == condName {
			if cond.Status == metav1.ConditionStatus(condValue) {
				// an empty Reason string means "Match any reason".
				if condReason == "" || cond.Reason == condReason {
					return true
				}
				t.Logf("%s condition Reason set to %s, expected %s", condName, cond.Reason, condReason)
			}

			t.Logf("%s condition set to %s, expected %s", condName, cond.Status, condValue)
		}
	}

	t.Logf("%s was not in conditions list", condName)
	return false
}

func findPodConditionInList(t *testing.T, conditions []v1.PodCondition, condName, condValue string) bool {
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
