/*
Copyright 2026 The Kubernetes Authors.

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
		CNPBaselineTierSamePriority,
	)
}

var CNPBaselineTierSamePriority = suite.ConformanceTest{
	ShortName:   "CNPBaselineTierSamePriority",
	Description: "Tests that ClusterNetworkPolicies in the Baseline tier with the same priority are all applied, both when they share a subject with disjoint rules and when they reference the same peer from different subjects, in both ingress and egress directions",
	Features: []suite.SupportedFeature{
		suite.SupportClusterNetworkPolicy,
	},
	Manifests: []string{"base/baseline_tier/standard-same-priority.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		// The manifest contains three policies at the same priority, each with the
		// same rule in both the ingress and egress direction:
		//   baseline-same-priority-gryffindor-slytherin: subject gryffindor, denies slytherin at port 80
		//   baseline-same-priority-gryffindor-hufflepuff: subject gryffindor, denies hufflepuff at port 80
		//   baseline-same-priority-hufflepuff-slytherin: subject hufflepuff, denies slytherin at port 8080
		// The first two share a subject with disjoint peers; the first and third
		// reference the same peer from different subjects. The differing ports
		// make any cross-application of one policy's rules to another policy's
		// subject observable. The Baseline tier rules take effect because no
		// NetworkPolicy selects these pods.
		gryffindorServer := kubernetes.GetPod(t, s.Client, "network-policy-conformance-gryffindor", "harry-potter-1", s.TimeoutConfig.GetTimeout)
		slytherinServer := kubernetes.GetPod(t, s.Client, "network-policy-conformance-slytherin", "draco-malfoy-1", s.TimeoutConfig.GetTimeout)
		hufflepuffServer := kubernetes.GetPod(t, s.Client, "network-policy-conformance-hufflepuff", "cedric-diggory-1", s.TimeoutConfig.GetTimeout)
		ravenclawServer := kubernetes.GetPod(t, s.Client, "network-policy-conformance-ravenclaw", "luna-lovegood-1", s.TimeoutConfig.GetTimeout)

		// The deny probes run first: observing every policy's Deny rules in both
		// directions proves all three policies are programmed, so the allow
		// probes below cannot pass vacuously while programming is in progress.
		t.Run("Should deny traffic in both directions for each same-priority policy", func(t *testing.T) {
			// baseline-same-priority-gryffindor-slytherin ingress: deny from slytherin to gryffindor at port 80
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-0", "tcp",
				gryffindorServer.Status.PodIP, int32(80), s.TimeoutConfig, false)
			// baseline-same-priority-gryffindor-slytherin egress: deny from gryffindor to slytherin at port 80
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "tcp",
				slytherinServer.Status.PodIP, int32(80), s.TimeoutConfig, false)
			// baseline-same-priority-gryffindor-hufflepuff ingress: deny from hufflepuff to gryffindor at port 80
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-0", "tcp",
				gryffindorServer.Status.PodIP, int32(80), s.TimeoutConfig, false)
			// baseline-same-priority-gryffindor-hufflepuff egress: deny from gryffindor to hufflepuff at port 80
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-1", "tcp",
				hufflepuffServer.Status.PodIP, int32(80), s.TimeoutConfig, false)
			// baseline-same-priority-hufflepuff-slytherin ingress: deny from slytherin to hufflepuff at port 8080
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-1", "tcp",
				hufflepuffServer.Status.PodIP, int32(8080), s.TimeoutConfig, false)
			// baseline-same-priority-hufflepuff-slytherin egress: deny from hufflepuff to slytherin at port 8080
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-1", "tcp",
				slytherinServer.Status.PodIP, int32(8080), s.TimeoutConfig, false)
		})

		t.Run("Should not apply one same-priority policy's rules to another policy's subject", func(t *testing.T) {
			// baseline-same-priority-hufflepuff-slytherin's port-8080 rules must
			// not bleed onto subject gryffindor: slytherin to gryffindor at port
			// 8080 matches no policy and must stay allowed
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-0", "tcp",
				gryffindorServer.Status.PodIP, int32(8080), s.TimeoutConfig, true)
			// same check in the egress direction: gryffindor to slytherin at port 8080
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "tcp",
				slytherinServer.Status.PodIP, int32(8080), s.TimeoutConfig, true)
			// baseline-same-priority-gryffindor-slytherin's port-80 rules must not
			// bleed onto subject hufflepuff: slytherin to hufflepuff at port 80
			// matches no policy and must stay allowed
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-1", "tcp",
				hufflepuffServer.Status.PodIP, int32(80), s.TimeoutConfig, true)
			// same check in the egress direction: hufflepuff to slytherin at port 80
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-0", "tcp",
				slytherinServer.Status.PodIP, int32(80), s.TimeoutConfig, true)
		})

		t.Run("Should not affect traffic matching no same-priority policy", func(t *testing.T) {
			// ravenclaw is referenced by no policy: traffic to and from the shared
			// subject gryffindor must stay allowed even at a denied port
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-ravenclaw", "luna-lovegood-0", "tcp",
				gryffindorServer.Status.PodIP, int32(80), s.TimeoutConfig, true)
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "tcp",
				ravenclawServer.Status.PodIP, int32(80), s.TimeoutConfig, true)
		})
	},
}
