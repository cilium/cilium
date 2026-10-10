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
		CNPAdminTierEgressUDP,
	)
}

var CNPAdminTierEgressUDP = suite.ConformanceTest{
	ShortName:   "CNPAdminTierEgressUDP",
	Description: "Tests support for egress traffic (UDP protocol) using cluster network policy API based on a server and client model",
	Features: []suite.SupportedFeature{
		suite.SupportClusterNetworkPolicy,
	},
	Manifests: []string{"base/admin_tier/standard-egress-udp-rules.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {

		t.Run("Should support an 'allow-egress' policy for UDP protocol; ensure rule ordering is respected", func(t *testing.T) {
			// This test uses `egress-udp` admin CNP
			// luna-lovegood-0 is our server pod in ravenclaw namespace
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-ravenclaw", "luna-lovegood-0", s.TimeoutConfig.GetTimeout)
			// cedric-diggory-0 is our client pod in hufflepuff namespace
			// ensure egress is ALLOWED to ravenclaw from hufflepuff
			// egressRule at index0 will take precedence over egressRule at index1; thus ALLOW takes precedence over DENY since rules are ordered
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-0", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, true)
			// cedric-diggory-1 is our client pod in hufflepuff namespace
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-1", "udp",
				serverPod.Status.PodIP, int32(5353), s.TimeoutConfig, true)
		})

		t.Run("Should support an 'allow-egress' policy for UDP protocol at the specified port", func(t *testing.T) {
			// This test uses `egress-udp` admin CNP
			// harry-potter-1 is our server pod in gryffindor namespace
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-gryffindor", "harry-potter-1", s.TimeoutConfig.GetTimeout)
			// cedric-diggory-0 is our client pod in hufflepuff namespace
			// ensure egress is ALLOWED to gryffindor from hufflepuff at port 53; egressRule at index5
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-0", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, true)
			// cedric-diggory-1 is our client pod in hufflepuff namespace
			// ensure egress is DENIED to gryffindor from hufflepuff for rest of the traffic; egressRule at index6
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-1", "udp",
				serverPod.Status.PodIP, int32(5353), s.TimeoutConfig, false)
		})

		t.Run("Should support an 'deny-egress' policy for UDP protocol; ensure rule ordering is respected", func(t *testing.T) {
			// This test uses `egress-udp` admin CNP
			// luna-lovegood-1 is our server pod in ravenclaw namespace
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-ravenclaw", "luna-lovegood-1", s.TimeoutConfig.GetTimeout)
			cnp := kubernetes.GetClusterNetworkPolicy(t, s.Client, "egress-udp", s.TimeoutConfig.GetTimeout)
			mutate := cnp.DeepCopy()
			// swap rules at index0 and index1
			allowRule := mutate.Spec.Egress[0]
			mutate.Spec.Egress[0] = mutate.Spec.Egress[1]
			mutate.Spec.Egress[1] = allowRule
			kubernetes.PatchClusterNetworkPolicy(t, s.Client, cnp, mutate, s.TimeoutConfig.GetTimeout)
			// cedric-diggory-0 is our client pod in hufflepuff namespace
			// ensure egress is DENIED to ravenclaw to hufflepuff
			// egressRule at index0 will take precedence over egressRule at index1; thus DENY takes precedence over ALLOW since rules are ordered
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-0", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, false)
			// cedric-diggory-1 is our client pod in hufflepuff namespace
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-1", "udp",
				serverPod.Status.PodIP, int32(5353), s.TimeoutConfig, false)
		})

		t.Run("Should support a 'deny-egress' policy for UDP protocol at the specified port", func(t *testing.T) {
			// This test uses `egress-udp` admin CNP
			// draco-malfoy-0 is our server pod in slytherin namespace
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-slytherin", "draco-malfoy-0", s.TimeoutConfig.GetTimeout)
			// cedric-diggory-0 is our client pod in hufflepuff namespace
			// ensure egress to slytherin is DENIED from hufflepuff at port 80; egressRule at index3 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-0", "udp",
				serverPod.Status.PodIP, int32(5353), s.TimeoutConfig, false)
			// cedric-diggory-0 is our client pod in hufflepuff namespace
			// ensure egress to slytherin is ALLOWED from hufflepuff for rest of the traffic; matches no rules hence allowed
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-1", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, true)
		})

		t.Run("Should support an 'pass-egress' policy for UDP protocol; ensure rule ordering is respected", func(t *testing.T) {
			// This test uses `egress-udp` admin CNP
			// luna-lovegood-1 is our server pod in ravenclaw namespace
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-ravenclaw", "luna-lovegood-1", s.TimeoutConfig.GetTimeout)
			cnp := kubernetes.GetClusterNetworkPolicy(t, s.Client, "egress-udp", s.TimeoutConfig.GetTimeout)
			mutate := cnp.DeepCopy()
			// swap rules at index0 and index2
			denyRule := mutate.Spec.Egress[0]
			mutate.Spec.Egress[0] = mutate.Spec.Egress[2]
			mutate.Spec.Egress[2] = denyRule
			kubernetes.PatchClusterNetworkPolicy(t, s.Client, cnp, mutate, s.TimeoutConfig.GetTimeout)
			// cedric-diggory-0 is our client pod in hufflepuff namespace
			// ensure egress is PASSED to ravenclaw from hufflepuff
			// egressRule at index0 will take precedence over egressRule at index1&index2; thus PASS takes precedence over ALLOW/DENY since rules are ordered
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-0", "udp",
				serverPod.Status.PodIP, int32(5353), s.TimeoutConfig, true)
			// cedric-diggory-1 is our client pod in hufflepuff namespace
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-1", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, true)
		})

		t.Run("Should support a 'pass-egress' policy for UDP protocol at the specified port", func(t *testing.T) {
			// This test uses `egress-udp` admin CNP
			// draco-malfoy-0 is our server pod in slytherin namespace
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-slytherin", "draco-malfoy-0", s.TimeoutConfig.GetTimeout)
			cnp := kubernetes.GetClusterNetworkPolicy(t, s.Client, "egress-udp", s.TimeoutConfig.GetTimeout)
			mutate := cnp.DeepCopy()
			// swap rules at index3 and index4
			denyRule := mutate.Spec.Egress[3]
			mutate.Spec.Egress[3] = mutate.Spec.Egress[4]
			mutate.Spec.Egress[4] = denyRule
			kubernetes.PatchClusterNetworkPolicy(t, s.Client, cnp, mutate, s.TimeoutConfig.GetTimeout)
			// cedric-diggory-0 is our client pod in hufflepuff namespace
			// ensure egress to slytherin is PASSED from hufflepuff at port 5353; egressRule at index3 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-0", "udp",
				serverPod.Status.PodIP, int32(5353), s.TimeoutConfig, true)
			// cedric-diggory-1 is our client pod in hufflepuff namespace
			// ensure egress to slytherin is ALLOWED from hufflepuff for rest of the traffic; matches no rules hence allowed
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-1", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, true)
		})
	},
}
