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

// conformanceRoleLabel is the pod label the pod selector tests add and remove to exercise label changes.
const conformanceRoleLabel = "conformance-role"

func init() {
	ConformanceTests = append(ConformanceTests,
		CNPAdminTierPodSelector,
	)
}

var CNPAdminTierPodSelector = suite.ConformanceTest{
	ShortName:   "CNPAdminTierPodSelector",
	Description: "Tests support for pod selectors in the subject and peers of ClusterNetworkPolicy on Admin Tier, used alone and combined with namespace selectors, with Accept and Deny rules, a port-restricted rule, and pod label changes",
	Features: []suite.SupportedFeature{
		suite.SupportClusterNetworkPolicy,
	},
	Manifests: []string{"base/admin_tier/standard-pod-selector-rules.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {

		t.Run("Should support pod selectors in egress peers", func(t *testing.T) {
			// This test uses `pod-selector-rules` admin CNP whose subject selects gryffindor pods
			// by pod label alone (namespaceSelector omitted).

			// luna-lovegood-0 is our server pod in ravenclaw namespace
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-ravenclaw", "luna-lovegood-0", s.TimeoutConfig.GetTimeout)
			// egress rule at index 0 (allow-to-luna-lovegood-0-tcp-80) only matches TCP port 80, so on port 8080
			// the egress rule at index 1 (deny-to-ravenclaw-pods) applies -> DENIED
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "tcp",
				serverPod.Status.PodIP, int32(8080), s.TimeoutConfig, false)
			// egress rule at index 0 accepts luna-lovegood-0 (selected by pod name) on TCP port 80, taking
			// precedence over the deny at index 1 -> ALLOWED
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, true)

			// luna-lovegood-1 is not selected by the accept at index 0, so the deny at index 1 (ravenclaw pods by
			// pod label alone) applies; harry-potter-1 is the client to show both gryffindor pods are subjects -> DENIED
			serverPod = kubernetes.GetPod(t, s.Client, "network-policy-conformance-ravenclaw", "luna-lovegood-1", s.TimeoutConfig.GetTimeout)
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-1", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, false)
		})

		t.Run("Should support pod selectors in ingress peers", func(t *testing.T) {
			// This test uses `pod-selector-rules` admin CNP; harry-potter-x are our server pods in the gryffindor subject.
			// The base pods are shared by every test, so always strip the label added below.
			t.Cleanup(func() {
				kubernetes.RemovePodLabel(t, s.Client, "network-policy-conformance-hufflepuff", "cedric-diggory-0", conformanceRoleLabel, s.TimeoutConfig.GetTimeout)
				kubernetes.RemovePodLabel(t, s.Client, "network-policy-conformance-hufflepuff", "cedric-diggory-1", conformanceRoleLabel, s.TimeoutConfig.GetTimeout)
			})

			// ingress rule at index 1 (deny-from-slytherin-pods) selects slytherin pods by pod label alone -> DENIED
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-gryffindor", "harry-potter-1", s.TimeoutConfig.GetTimeout)
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-1", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, false)

			// ingress rule at index 0 (allow-from-draco-malfoy-0) accepts draco-malfoy-0 (selected by pod name),
			// taking precedence over the deny at index 1 -> ALLOWED
			serverPod = kubernetes.GetPod(t, s.Client, "network-policy-conformance-gryffindor", "harry-potter-0", s.TimeoutConfig.GetTimeout)
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-0", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, true)

			// label cedric-diggory-0 so that ingress rule at index 2 (deny-from-blocked-hufflepuff-pods) starts matching it -> DENIED
			kubernetes.SetPodLabel(t, s.Client, "network-policy-conformance-hufflepuff", "cedric-diggory-0", conformanceRoleLabel, "blocked", s.TimeoutConfig.GetTimeout)
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-0", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, false)
			// cedric-diggory-1 lives in the same namespace but carries no such label -> ALLOWED
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-1", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, true)
			// remove the label again: the rule stops matching cedric-diggory-0 -> ALLOWED
			kubernetes.RemovePodLabel(t, s.Client, "network-policy-conformance-hufflepuff", "cedric-diggory-0", conformanceRoleLabel, s.TimeoutConfig.GetTimeout)
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-0", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, true)
			// label cedric-diggory-1 instead: the rule starts matching it -> DENIED
			kubernetes.SetPodLabel(t, s.Client, "network-policy-conformance-hufflepuff", "cedric-diggory-1", conformanceRoleLabel, "blocked", s.TimeoutConfig.GetTimeout)
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-1", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, false)
		})

		t.Run("Should support pod selectors in the subject", func(t *testing.T) {
			// The base pods are shared by every test, so always strip the label added below.
			t.Cleanup(func() {
				kubernetes.RemovePodLabel(t, s.Client, "network-policy-conformance-ravenclaw", "luna-lovegood-0", conformanceRoleLabel, s.TimeoutConfig.GetTimeout)
				kubernetes.RemovePodLabel(t, s.Client, "network-policy-conformance-ravenclaw", "luna-lovegood-1", conformanceRoleLabel, s.TimeoutConfig.GetTimeout)
			})

			// draco-malfoy-0 is not selected by the `pod-selector-rules` subject, even though its
			// namespaceSelector is omitted, so the egress deny at index 1 must not apply to it -> ALLOWED
			// (if the subject podSelector were ignored, every pod would be a subject and this would be denied)
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-ravenclaw", "luna-lovegood-1", s.TimeoutConfig.GetTimeout)
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-0", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, true)

			// This part uses `label-selected-subject-rules` admin CNP whose subject is ravenclaw pods labeled
			// conformance-role=restricted; draco-malfoy-0 is our server pod in slytherin namespace
			serverPod = kubernetes.GetPod(t, s.Client, "network-policy-conformance-slytherin", "draco-malfoy-0", s.TimeoutConfig.GetTimeout)

			// label luna-lovegood-0: it becomes a subject and egress rule at index 0 (deny-to-slytherin) applies -> DENIED
			kubernetes.SetPodLabel(t, s.Client, "network-policy-conformance-ravenclaw", "luna-lovegood-0", conformanceRoleLabel, "restricted", s.TimeoutConfig.GetTimeout)
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-ravenclaw", "luna-lovegood-0", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, false)
			// luna-lovegood-1 lives in the same namespace but is not labeled, so it is not a subject -> ALLOWED
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-ravenclaw", "luna-lovegood-1", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, true)
			// remove the label again: luna-lovegood-0 stops being a subject -> ALLOWED
			kubernetes.RemovePodLabel(t, s.Client, "network-policy-conformance-ravenclaw", "luna-lovegood-0", conformanceRoleLabel, s.TimeoutConfig.GetTimeout)
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-ravenclaw", "luna-lovegood-0", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, true)
			// label luna-lovegood-1 instead: it becomes a subject -> DENIED
			kubernetes.SetPodLabel(t, s.Client, "network-policy-conformance-ravenclaw", "luna-lovegood-1", conformanceRoleLabel, "restricted", s.TimeoutConfig.GetTimeout)
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-ravenclaw", "luna-lovegood-1", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, false)
		})
	},
}
