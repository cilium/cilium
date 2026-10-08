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
	"testing"

	"sigs.k8s.io/network-policy-api/conformance/utils/kubernetes"
	"sigs.k8s.io/network-policy-api/conformance/utils/suite"
)

func init() {
	ConformanceTests = append(ConformanceTests,
		CNPAdminTierIngressUDP,
		CNPAdminTierIngressNamedPort,
	)
}

var CNPAdminTierIngressUDP = suite.ConformanceTest{
	ShortName:   "CNPAdminTierIngressUDP",
	Description: "Tests support for ingress traffic (UDP protocol) using cluster network policy API based on a server and client model",
	Features: []suite.SupportedFeature{
		suite.SupportClusterNetworkPolicy,
	},
	Manifests: []string{"base/admin_tier/standard-ingress-udp-rules.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {

		t.Run("Should support an 'allow-ingress' policy for UDP protocol; ensure rule ordering is respected", func(t *testing.T) {
			// This test uses `ingress-udp` admin CNP
			// cedric-diggory-0 is our server pod in hufflepuff namespace
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-hufflepuff", "cedric-diggory-0", s.TimeoutConfig.GetTimeout)
			// luna-lovegood-0 is our client pod in ravenclaw namespace
			// ensure ingress is ALLOWED from ravenclaw to hufflepuff
			// ingressRule at index0 will take precedence over ingressRule at index1; thus ALLOW takes precedence over DENY since rules are ordered
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-ravenclaw", "luna-lovegood-0", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, true)
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-ravenclaw", "luna-lovegood-1", "udp",
				serverPod.Status.PodIP, int32(5353), s.TimeoutConfig, true)
		})

		t.Run("Should support an 'allow-ingress' policy for UDP protocol at the specified port", func(t *testing.T) {
			// This test uses `ingress-udp` admin CNP
			// cedric-diggory-1 is our server pod in hufflepuff namespace
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-hufflepuff", "cedric-diggory-1", s.TimeoutConfig.GetTimeout)
			// harry-potter-0 is our client pod in gryffindor namespace
			// ensure ingress is ALLOWED from gryffindor to hufflepuff at port 53; ingressRule at index5
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, true)
			// harry-potter-1 is our client pod in gryfindor namespace
			// ensure ingress is DENIED from gryffindor to hufflepuff for rest of the traffic; ingressRule at index6 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-1", "udp",
				serverPod.Status.PodIP, int32(5353), s.TimeoutConfig, false)
		})

		t.Run("Should support an 'deny-ingress' policy for UDP protocol; ensure rule ordering is respected", func(t *testing.T) {
			// This test uses `ingress-udp` admin CNP
			// cedric-diggory-1 is our server pod in hufflepuff namespace
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-hufflepuff", "cedric-diggory-1", s.TimeoutConfig.GetTimeout)
			cnp := kubernetes.GetClusterNetworkPolicy(t, s.Client, "ingress-udp", s.TimeoutConfig.GetTimeout)
			mutate := cnp.DeepCopy()
			// swap rules at index0 and index1
			allowRule := mutate.Spec.Ingress[0]
			mutate.Spec.Ingress[0] = mutate.Spec.Ingress[1]
			mutate.Spec.Ingress[1] = allowRule
			kubernetes.PatchClusterNetworkPolicy(t, s.Client, cnp, mutate, s.TimeoutConfig.GetTimeout)
			// luna-lovegood-0 is our client pod in ravenclaw namespace
			// ensure ingress is DENIED from ravenclaw to hufflepuff
			// ingressRule at index0 will take precedence over ingressRule at index1; thus DENY takes precedence over ALLOW since rules are ordered
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-ravenclaw", "luna-lovegood-0", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, false)
			// luna-lovegood-1 is our client pod in ravenclaw namespace
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-ravenclaw", "luna-lovegood-1", "udp",
				serverPod.Status.PodIP, int32(5353), s.TimeoutConfig, false)
		})

		t.Run("Should support a 'deny-ingress' policy for UDP protocol at the specified port", func(t *testing.T) {
			// This test uses `ingress-udp` admin CNP
			// cedric-diggory-0 is our server pod in hufflepuff namespace
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-hufflepuff", "cedric-diggory-0", s.TimeoutConfig.GetTimeout)
			// draco-malfoy-0 is our client pod in slytherin namespace
			// ensure ingress from slytherin is DENIED to hufflepuff at port 80; ingressRule at index3 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-0", "udp",
				serverPod.Status.PodIP, int32(5353), s.TimeoutConfig, false)
			// draco-malfoy-1 is our client pod in slytherin namespace
			// ensure ingress from slytherin is ALLOWED to hufflepuff for rest of the traffic; matches no rules hence allowed
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-1", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, true)
		})

		t.Run("Should support an 'pass-ingress' policy for UDP protocol; ensure rule ordering is respected", func(t *testing.T) {
			// This test uses `ingress-udp` admin CNP
			// cedric-diggory-1 is our server pod in hufflepuff namespace
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-hufflepuff", "cedric-diggory-1", s.TimeoutConfig.GetTimeout)
			cnp := kubernetes.GetClusterNetworkPolicy(t, s.Client, "ingress-udp", s.TimeoutConfig.GetTimeout)
			mutate := cnp.DeepCopy()
			// swap rules at index0 and index2
			denyRule := mutate.Spec.Ingress[0]
			mutate.Spec.Ingress[0] = mutate.Spec.Ingress[2]
			mutate.Spec.Ingress[2] = denyRule
			kubernetes.PatchClusterNetworkPolicy(t, s.Client, cnp, mutate, s.TimeoutConfig.GetTimeout)
			// luna-lovegood-0 is our client pod in ravenclaw namespace
			// ensure ingress is PASSED from ravenclaw to hufflepuff
			// ingressRule at index0 will take precedence over ingressRule at index1&index2; thus PASS takes precedence over ALLOW/DENY since rules are ordered
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-ravenclaw", "luna-lovegood-0", "udp",
				serverPod.Status.PodIP, int32(5353), s.TimeoutConfig, true)
			// luna-lovegood-1 is our client pod in ravenclaw namespace
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-ravenclaw", "luna-lovegood-1", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, true)
		})

		t.Run("Should support a 'pass-ingress' policy for UDP protocol at the specified port", func(t *testing.T) {
			// This test uses `ingress-udp` admin CNP
			// cedric-diggory-0 is our server pod in hufflepuff namespace
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-hufflepuff", "cedric-diggory-0", s.TimeoutConfig.GetTimeout)
			cnp := kubernetes.GetClusterNetworkPolicy(t, s.Client, "ingress-udp", s.TimeoutConfig.GetTimeout)
			mutate := cnp.DeepCopy()
			// swap rules at index3 and index4
			denyRule := mutate.Spec.Ingress[3]
			mutate.Spec.Ingress[3] = mutate.Spec.Ingress[4]
			mutate.Spec.Ingress[4] = denyRule
			kubernetes.PatchClusterNetworkPolicy(t, s.Client, cnp, mutate, s.TimeoutConfig.GetTimeout)
			// draco-malfoy-0 is our client pod in slytherin namespace
			// ensure ingress from slytherin is PASSED to hufflepuff at port 5353; ingressRule at index3 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-0", "udp",
				serverPod.Status.PodIP, int32(5353), s.TimeoutConfig, true)
			// draco-malfoy-1 is our client pod in slytherin namespace
			// ensure ingress from slytherin is ALLOWED to hufflepuff for rest of the traffic; matches no rules hence allowed
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-1", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, true)
		})
	},
}
