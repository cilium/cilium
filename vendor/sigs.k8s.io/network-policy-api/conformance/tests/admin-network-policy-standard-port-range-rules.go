/*
Copyright 2024 The Kubernetes Authors.

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
		CNPAdminTierPortRange,
	)
}

var CNPAdminTierPortRange = suite.ConformanceTest{
	ShortName:   "CNPAdminTierPortRange",
	Description: "Tests support for combined ingress and egress port range rules across protocols in ClusterNetworkPolicy on Admin Tier",
	Features: []suite.SupportedFeature{
		suite.SupportClusterNetworkPolicy,
	},
	Manifests: []string{"base/admin_tier/standard-port-range-rules-combined.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {

		t.Run("Should support egress port range rules across different protocols", func(t *testing.T) {
			// This test uses `port-range-rules` admin CNP where Subject is gryffindor.

			// Egress to ravenclaw (TCP port range 80-8080)
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-ravenclaw", "luna-lovegood-0", s.TimeoutConfig.GetTimeout)
			// TCP port 80 (in range) -> ALLOWED
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, true)
			// TCP port 8080 (in range) -> ALLOWED
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "tcp",
				serverPod.Status.PodIP, int32(8080), s.TimeoutConfig, true)
			// UDP port 53 (not in TCP rule, caught by deny-all-egress) -> DENIED
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-1", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, false)

			// Egress to hufflepuff (UDP port range 53-5353)
			serverPod = kubernetes.GetPod(t, s.Client, "network-policy-conformance-hufflepuff", "cedric-diggory-0", s.TimeoutConfig.GetTimeout)
			// UDP port 53 (in range) -> ALLOWED
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, true)
			// UDP port 5353 (in range) -> ALLOWED
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "udp",
				serverPod.Status.PodIP, int32(5353), s.TimeoutConfig, true)
			// TCP port 80 (not in UDP rule, caught by deny-all-egress) -> DENIED
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-1", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, false)

			// Egress to slytherin (SCTP port range 9003-9005)
			serverPod = kubernetes.GetPod(t, s.Client, "network-policy-conformance-slytherin", "draco-malfoy-0", s.TimeoutConfig.GetTimeout)
			// SCTP port 9003 (in range) -> ALLOWED
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "sctp",
				serverPod.Status.PodIP, int32(9003), s.TimeoutConfig, true)
			// SCTP port 9005 (in range) -> ALLOWED
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "sctp",
				serverPod.Status.PodIP, int32(9005), s.TimeoutConfig, true)
			// TCP port 80 (not in SCTP rule, caught by deny-all-egress) -> DENIED
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-1", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, false)
		})

		t.Run("Should support ingress port range rules across different protocols", func(t *testing.T) {
			// This test uses `port-range-rules` admin CNP where Subject is gryffindor.

			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-gryffindor", "harry-potter-0", s.TimeoutConfig.GetTimeout)

			// Ingress from ravenclaw (TCP port range 80-8080)
			// TCP port 80 (in range) -> ALLOWED
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-ravenclaw", "luna-lovegood-0", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, true)
			// TCP port 8080 (in range) -> ALLOWED
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-ravenclaw", "luna-lovegood-0", "tcp",
				serverPod.Status.PodIP, int32(8080), s.TimeoutConfig, true)
			// UDP port 53 (not in TCP rule, caught by deny-all-ingress) -> DENIED
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-ravenclaw", "luna-lovegood-1", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, false)

			// Ingress from hufflepuff (UDP port range 53-5353)
			// UDP port 53 (in range) -> ALLOWED
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-0", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, true)
			// UDP port 5353 (in range) -> ALLOWED
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-0", "udp",
				serverPod.Status.PodIP, int32(5353), s.TimeoutConfig, true)
			// TCP port 80 (not in UDP rule, caught by deny-all-ingress) -> DENIED
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-1", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, false)

			// Ingress from slytherin (SCTP port range 9003-9005)
			// SCTP port 9003 (in range) -> ALLOWED
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-0", "sctp",
				serverPod.Status.PodIP, int32(9003), s.TimeoutConfig, true)
			// SCTP port 9005 (in range) -> ALLOWED
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-0", "sctp",
				serverPod.Status.PodIP, int32(9005), s.TimeoutConfig, true)
			// TCP port 80 (not in SCTP rule, caught by deny-all-ingress) -> DENIED
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-1", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, false)
		})
	},
}
