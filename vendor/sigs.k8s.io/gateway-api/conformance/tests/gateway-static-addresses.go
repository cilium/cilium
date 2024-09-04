/*
Copyright 2023 The Kubernetes Authors.

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

package tests

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, GatewayStaticAddresses)
}

// GatewayStaticAddresses tests the implementation's support of deploying
// Gateway resources with static addresses, or in other words addresses
// provided via the specification rather than relying on the underlying
// implementation/network to dynamically assign the Gateway an address.
//
// Running this test against your own implementation is currently a little bit
// messy, as at the time of writing we didn't have great ways to provide the
// test suite with things like known good, or known bad addresses to run the
// test with (as we obviously can't determine that for the implementation).
//
// As such, if you're trying to enable this test for yourself and you're getting
// confused about how to provide addresses, you'll actually do that in the
// conformance test suite BEFORE you even set up and run your tests. Make sure
// you populate the following test suite fields:
//
//   - suite.UsableNetworkAddresses
//   - suite.UnusableNetworkAddresses
//
// With appropriate network addresses for your network environment.
var GatewayStaticAddresses = suite.ConformanceTest{
	ShortName:   "GatewayStaticAddresses",
	Description: "A Gateway in the gateway-conformance-infra namespace should be able to use previously determined addresses.",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportGatewayStaticAddresses,
	},
	Manifests: []string{
		"tests/gateway-static-addresses.yaml",
	},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		gwNN := types.NamespacedName{
			Name:      "gateway-static-addresses",
			Namespace: "gateway-conformance-infra",
		}
		ctx, cancel := context.WithTimeout(context.Background(), s.TimeoutConfig.DefaultTestTimeout)
		defer cancel()

		t.Logf("waiting for namespace %s and Gateway %s to be ready for testing", gwNN.Namespace, gwNN.Name)
		kubernetes.GatewayMustHaveLatestConditions(t, s.Client, s.TimeoutConfig, gwNN)

		t.Logf("retrieving Gateway %s/%s and noting the provided addresses", gwNN.Namespace, gwNN.Name)
		currentGW := &v1.Gateway{}
		err := s.Client.Get(ctx, gwNN, currentGW)
		require.NoError(t, err, "error getting Gateway: %v", err)
		require.Len(t, currentGW.Spec.Addresses, 3, "expected 3 addresses on the Gateway, one invalid, one usable and one unusable. somehow got %d", len(currentGW.Spec.Addresses))
		invalidAddress := currentGW.Spec.Addresses[0]
		unusableAddress := currentGW.Spec.Addresses[1]
		usableAddress := currentGW.Spec.Addresses[2]

		t.Logf("verifying that the Gateway %s/%s is NOT accepted due to an address type that the implementation doesn't support", gwNN.Namespace, gwNN.Name)
		kubernetes.GatewayMustHaveCondition(t, s.Client, s.TimeoutConfig, gwNN, metav1.Condition{
			Type:   string(v1.GatewayConditionAccepted),
			Status: metav1.ConditionFalse,
			Reason: string(v1.GatewayReasonUnsupportedAddress),
		})

		t.Logf("patching Gateway %s/%s to remove the invalid address %s", gwNN.Namespace, gwNN.Name, invalidAddress.Value)
		updatedGW := currentGW.DeepCopy()
		updatedGW.Spec.Addresses = filterAddr(currentGW.Spec.Addresses, invalidAddress)
		err = s.Client.Patch(ctx, updatedGW, client.MergeFrom(currentGW))
		require.NoError(t, err, "failed to patch Gateway: %v", err)
		kubernetes.GatewayMustHaveLatestConditions(t, s.Client, s.TimeoutConfig, gwNN)

		t.Logf("verifying that the Gateway %s/%s is now accepted, but is not programmed due to an address that can't be used", gwNN.Namespace, gwNN.Name)
		err = s.Client.Get(ctx, gwNN, currentGW)
		require.NoError(t, err, "error getting Gateway: %v", err)
		kubernetes.GatewayMustHaveCondition(t, s.Client, s.TimeoutConfig, gwNN, metav1.Condition{
			Type:   string(v1.GatewayConditionAccepted),
			Status: metav1.ConditionTrue,
			Reason: string(v1.GatewayReasonAccepted),
		})
		kubernetes.GatewayMustHaveCondition(t, s.Client, s.TimeoutConfig, gwNN, metav1.Condition{
			Type:   string(v1.GatewayConditionProgrammed),
			Status: metav1.ConditionFalse,
			Reason: string(v1.GatewayReasonAddressNotUsable),
		})

		t.Logf("patching Gateway %s/%s to remove the unusable address %s", gwNN.Namespace, gwNN.Name, unusableAddress.Value)
		updatedGW = currentGW.DeepCopy()
		updatedGW.Spec.Addresses = filterAddr(currentGW.Spec.Addresses, unusableAddress)
		err = s.Client.Patch(ctx, updatedGW, client.MergeFrom(currentGW))
		require.NoError(t, err, "failed to patch Gateway: %v", err)
		kubernetes.GatewayMustHaveLatestConditions(t, s.Client, s.TimeoutConfig, gwNN)

		t.Logf("verifying that the Gateway %s/%s is accepted and programmed with the usable static address %s assigned", gwNN.Namespace, gwNN.Name, usableAddress.Value)
		err = s.Client.Get(ctx, gwNN, currentGW)
		require.NoError(t, err, "error getting Gateway: %v", err)
		kubernetes.GatewayMustHaveCondition(t, s.Client, s.TimeoutConfig, gwNN, metav1.Condition{
			Type:   string(v1.GatewayConditionAccepted),
			Status: metav1.ConditionTrue,
			Reason: string(v1.GatewayReasonAccepted),
		})
		kubernetes.GatewayMustHaveCondition(t, s.Client, s.TimeoutConfig, gwNN, metav1.Condition{
			Type:   string(v1.GatewayConditionProgrammed),
			Status: metav1.ConditionTrue,
			Reason: string(v1.GatewayReasonProgrammed),
		})
		kubernetes.GatewayStatusMustHaveListeners(t, s.Client, s.TimeoutConfig, gwNN, finalExpectedListenerState)
		require.Len(t, currentGW.Spec.Addresses, 1, "expected only 1 address left specified on Gateway")
		statusAddresses := extractStatusAddresses(currentGW.Status.Addresses)
		require.NotContains(t, statusAddresses, unusableAddress.Value, "should contain the unusable address")
		require.NotContains(t, statusAddresses, invalidAddress.Value, "should contain the invalid address")
		require.Contains(t, statusAddresses, usableAddress.Value, "should contain the usable address")
		for _, addr := range currentGW.Status.Addresses {
			if usableAddress.Value != addr.Value {
				continue
			}
			require.Equal(t, usableAddress.Type, addr.Type, "expected address type to match the usable address")
		}
	},
}

func extractStatusAddresses(addresses []v1.GatewayStatusAddress) []string {
	res := []string{}
	for _, a := range addresses {
		n := a.Value
		res = append(res, n)
	}
	return res
}

// -----------------------------------------------------------------------------
// Private Helper Functions
// -----------------------------------------------------------------------------

func filterAddr(addrs []v1.GatewayAddress, filter v1.GatewayAddress) (newAddrs []v1.GatewayAddress) {
	for _, addr := range addrs {
		if addr.Value != filter.Value {
			newAddrs = append(newAddrs, addr)
		}
	}
	return
}

var finalExpectedListenerState = []v1.ListenerStatus{
	{
		Name: v1.SectionName("http"),
		SupportedKinds: []v1.RouteGroupKind{{
			Group: (*v1.Group)(&v1.GroupVersion.Group),
			Kind:  v1.Kind("HTTPRoute"),
		}},
		Conditions: []metav1.Condition{
			{
				Type:   string(v1.ListenerConditionAccepted),
				Status: metav1.ConditionTrue,
				Reason: "", // any reason
			},
			{
				Type:   string(v1.ListenerConditionResolvedRefs),
				Status: metav1.ConditionTrue,
				Reason: "", // any reason
			},
		},
		AttachedRoutes: 0,
	},
}
