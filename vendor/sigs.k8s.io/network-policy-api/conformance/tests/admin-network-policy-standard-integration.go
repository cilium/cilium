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

package tests

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	networkingv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "sigs.k8s.io/network-policy-api/apis/v1alpha2"
	"sigs.k8s.io/network-policy-api/conformance/utils/kubernetes"
	"sigs.k8s.io/network-policy-api/conformance/utils/suite"
)

func init() {
	ConformanceTests = append(ConformanceTests,
		CNPAdminTierIntegration,
	)
}

var CNPAdminTierIntegration = suite.ConformanceTest{
	ShortName:   "CNPAdminTierIntegration",
	Description: "Tests integration support for gress traffic between admin CNP, NP and baseline CNP using PASS action based on a server and client model",
	Features: []suite.SupportedFeature{
		suite.SupportClusterNetworkPolicy,
	},
	Manifests: []string{"base/api_integration/standard-anp-np-banp.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {

		t.Run("Should Deny traffic from slytherin to gryffindor respecting admin CNP", func(t *testing.T) {
			// This test uses `pass-example` admin CNP from api_integration/standard-anp-np-banp.yaml
			// harry-potter-0 is our server pod in gryffindor namespace
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-gryffindor", "harry-potter-0", s.TimeoutConfig.GetTimeout)
			// draco-malfoy-0 is our client pod in slytherin namespace
			// ensure ingress is DENIED to gryffindor from slytherin
			// inressRule at index0 will take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-0", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, false)
			// draco-malfoy-1 is our client pod in slytherin namespace
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-1", "tcp",
				serverPod.Status.PodIP, int32(8080), s.TimeoutConfig, false)
		})

		t.Run("Should Deny traffic to slytherin from gryffindor respecting admin CNP", func(t *testing.T) {
			// This test uses `pass-example` admin CNP from api_integration/standard-anp-np-banp.yaml
			// draco-malfoy-0 is our server pod in slytherin namespace
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-slytherin", "draco-malfoy-0", s.TimeoutConfig.GetTimeout)
			// harry-potter-0 is our client pod in gryffindor namespace
			// ensure egress is DENIED to slytherin from gryffindor
			// egressRule at index0 will take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, false)
			// harry-potter-1 is our client pod in gryffindor namespace
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-1", "tcp",
				serverPod.Status.PodIP, int32(8080), s.TimeoutConfig, false)
		})

		t.Run("Should support a 'pass-ingress' policy for admin CNP and respect the match for network policy", func(t *testing.T) {
			// This test uses `pass example` admin CNP from api_integration/standard-anp-np-banp.yaml
			// and alters the ingress rule action to "pass"
			cnp := kubernetes.GetClusterNetworkPolicy(t, s.Client, "pass-example", s.TimeoutConfig.GetTimeout)
			mutate := cnp.DeepCopy()
			// change ingress rule from "deny" to "pass"
			mutate.Spec.Ingress[0].Action = api.ClusterNetworkPolicyRuleActionPass
			kubernetes.PatchClusterNetworkPolicy(t, s.Client, cnp, mutate, s.TimeoutConfig.GetTimeout)
			// harry-potter-0 is our server pod in gryffindor namespace
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-gryffindor", "harry-potter-0", s.TimeoutConfig.GetTimeout)
			// draco-malfoy-0 is our client pod in slytherin namespace
			// ensure ingress is PASSED to gryffindor from slytherin - the underlying network policy ALLOW should take effect
			// inressRule at index0 will take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-0", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, true)
			// draco-malfoy-1 is our client pod in slytherin namespace
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-1", "tcp",
				serverPod.Status.PodIP, int32(8080), s.TimeoutConfig, true)
		})

		t.Run("Should support a 'pass-egress' policy for admin CNP and respect the match for network policy", func(t *testing.T) {
			// This test uses `pass example` admin CNP from api_integration/standard-anp-np-banp.yaml
			// and alters the egress rule action to "pass"
			cnp := kubernetes.GetClusterNetworkPolicy(t, s.Client, "pass-example", s.TimeoutConfig.GetTimeout)
			mutate := cnp.DeepCopy()
			// change egress rule from "deny" to "pass"
			mutate.Spec.Egress[0].Action = api.ClusterNetworkPolicyRuleActionPass
			kubernetes.PatchClusterNetworkPolicy(t, s.Client, cnp, mutate, s.TimeoutConfig.GetTimeout)
			// draco-malfoy-0 is our server pod in slytherin namespace
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-slytherin", "draco-malfoy-0", s.TimeoutConfig.GetTimeout)
			// harry-potter-0 is our client pod in gryffindor namespace
			// ensure egress is PASSED from gryffindor to slytherin - the underlying network policy ALLOW should take effect
			// egressRule at index0 will take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, true)
			// harry-potter-1 is our client pod in gryffindor namespace
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-1", "tcp",
				serverPod.Status.PodIP, int32(8080), s.TimeoutConfig, true)
		})

		t.Run("Should support a 'pass-ingress' policy for admin CNP and respect the match for baseline cluster network policy", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), s.TimeoutConfig.GetTimeout)
			defer cancel()
			// This test uses `default` baseline CNP from api_integration/standard-anp-np-banp.yaml
			np := &networkingv1.NetworkPolicy{}
			err := s.Client.Get(ctx, client.ObjectKey{
				Namespace: "network-policy-conformance-gryffindor",
				Name:      "allow-gress-from-to-slytherin-to-gryffindor",
			}, np)
			require.NoErrorf(t, err, "unable to fetch the network policy")
			// delete network policy so that baseline CNP takes effect
			err = s.Client.Delete(ctx, np)
			require.NoErrorf(t, err, "unable to delete the network policy")
			// harry-potter-0 is our server pod in gryffindor namespace
			clientPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-gryffindor", "harry-potter-0", s.TimeoutConfig.GetTimeout)
			// draco-malfoy-0 is our client pod in slytherin namespace
			// ensure ingress is PASSED to gryffindor from slytherin - the baseline cluster network policy DENY should take effect
			// inressRule at index0 will take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-0", "tcp",
				clientPod.Status.PodIP, int32(80), s.TimeoutConfig, false)
			// draco-malfoy-1 is our client pod in slytherin namespace
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-1", "tcp",
				clientPod.Status.PodIP, int32(8080), s.TimeoutConfig, false)
		})

		t.Run("Should support a 'pass-egress' policy for admin CNP and respect the match for baseline cluster network policy", func(t *testing.T) {
			// This test uses `default` baseline CNP from api_integration/standard-anp-np-banp.yaml
			// draco-malfoy-0 is our server pod in slytherin namespace
			clientPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-slytherin", "draco-malfoy-0", s.TimeoutConfig.GetTimeout)
			// harry-potter-0 is our client pod in gryffindor namespace
			// ensure ingress is PASSED to gryffindor from slytherin - the underlying baseline cluster network policy DENY should take effect
			// egressRule at index0 will take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "tcp",
				clientPod.Status.PodIP, int32(80), s.TimeoutConfig, false)
			// harry-potter-1 is our client pod in gryffindor namespace
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-1", "tcp",
				clientPod.Status.PodIP, int32(8080), s.TimeoutConfig, false)
		})
	},
}
