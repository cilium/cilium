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
		CNPBaselineTierGress,
	)
}

var CNPBaselineTierGress = suite.ConformanceTest{
	ShortName:   "CNPBaselineTierGress",
	Description: "Tests support for combined ingress and egress traffic rules in the baseline cluster network policy API based on a server and client model",
	Features: []suite.SupportedFeature{
		suite.SupportClusterNetworkPolicy,
	},
	Manifests: []string{"base/baseline_tier/standard-gress-rules-combined.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {

		t.Run("Should support an 'allow-gress' policy across different protocols", func(t *testing.T) {
			// This test uses `default` baseline CNP

			/* First; let's test egress works! */
			// luna-lovegood-0 is our server pod in ravenclaw namespace
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-ravenclaw", "luna-lovegood-0", s.TimeoutConfig.GetTimeout)
			// harry-potter-x is our client pod in gryffindor namespace
			// ensure egress is ALLOWED to ravenclaw from gryffindor
			// egressRule at index0 will take precedence over egressRule at index1; thus ALLOW takes precedence over DENY since rules are ordered
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, true)
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-1", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, true)
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "sctp",
				serverPod.Status.PodIP, int32(9003), s.TimeoutConfig, true)

			/* Second; let's test ingress works! */
			// harry-potter-0 is our server pod in gryffindor namespace
			serverPod = kubernetes.GetPod(t, s.Client, "network-policy-conformance-gryffindor", "harry-potter-0", s.TimeoutConfig.GetTimeout)
			// luna-lovegood-x is our client pod in ravenclaw namespace
			// ensure ingress is ALLOWED from ravenclaw to gryffindor
			// ingressRule at index0 will take precedence over ingressRule at index1; thus ALLOW takes precedence over DENY since rules are ordered
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-ravenclaw", "luna-lovegood-0", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, true)
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-ravenclaw", "luna-lovegood-1", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, true)
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-ravenclaw", "luna-lovegood-1", "sctp",
				serverPod.Status.PodIP, int32(9003), s.TimeoutConfig, true)
		})

		t.Run("Should support an 'allow-gress' policy across different protocols at the specified ports", func(t *testing.T) {
			// This test uses `default` baseline CNP

			/* First; let's test egress works! */
			// cedric-diggory-1 is our server pod in hufflepuff namespace
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-hufflepuff", "cedric-diggory-1", s.TimeoutConfig.GetTimeout)
			// harry-potter-0 is our client pod in gryffindor namespace
			// ensure egress is ALLOWED to hufflepuff from gryffindor at port 8080; egressRule at index5 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "tcp",
				serverPod.Status.PodIP, int32(8080), s.TimeoutConfig, true)
			// harry-potter-1 is our client pod in gryffindor namespace
			// ensure egress is DENIED to hufflepuff from gryffindor for rest of the traffic; egressRule at index6 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-1", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, false)
			// harry-potter-0 is our client pod in gryffindor namespace
			// ensure egress is ALLOWED to hufflepuff from gryffindor at port 5353; egressRule at index5 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "udp",
				serverPod.Status.PodIP, int32(5353), s.TimeoutConfig, true)
			// harry-potter-1 is our client pod in gryffindor namespace
			// ensure egress is DENIED to hufflepuff from gryffindor for rest of the traffic; egressRule at index6 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-1", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, false)
			// harry-potter-0 is our client pod in gryffindor namespace
			// ensure egress is ALLOWED to hufflepuff from gryffindor at port 9003; egressRule at index5 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "sctp",
				serverPod.Status.PodIP, int32(9003), s.TimeoutConfig, true)
			// harry-potter-1 is our client pod in gryffindor namespace
			// ensure egress is DENIED to hufflepuff from gryffindor for rest of the traffic; egressRule at index6 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-1", "sctp",
				serverPod.Status.PodIP, int32(9005), s.TimeoutConfig, false)

			/* Second; let's test ingress works! */
			// harry-potter-1 is our server pod in gryffindor namespace
			serverPod = kubernetes.GetPod(t, s.Client, "network-policy-conformance-gryffindor", "harry-potter-1", s.TimeoutConfig.GetTimeout)
			// cedric-diggory-0 is our client pod in hufflepuff namespace
			// ensure ingress is ALLOWED from hufflepuff to gryffindor at port 80; ingressRule at index5 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-0", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, true)
			// cedric-diggory-1 is our client pod in hufflepuff namespace
			// ensure ingress is DENIED from hufflepuff to gryffindor for rest of the traffic; ingressRule at index6 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-1", "tcp",
				serverPod.Status.PodIP, int32(8080), s.TimeoutConfig, false)
			// cedric-diggory-0 is our client pod in hufflepuff namespace
			// ensure ingress is ALLOWED from hufflepuff to gryffindor at port 5353; ingressRule at index5 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-0", "udp",
				serverPod.Status.PodIP, int32(5353), s.TimeoutConfig, true)
			// cedric-diggory-1 is our client pod in hufflepuff namespace
			// ensure ingress is DENIED from hufflepuff to gryffindor for rest of the traffic; ingressRule at index6 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-1", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, false)
			// cedric-diggory-0 is our client pod in hufflepuff namespace
			// ensure ingress is ALLOWED from hufflepuff to gryffindor at port 9003; ingressRule at index5 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-0", "sctp",
				serverPod.Status.PodIP, int32(9003), s.TimeoutConfig, true)
			// cedric-diggory-1 is our client pod in hufflepuff namespace
			// ensure ingress is DENIED from hufflepuff to gryffindor for rest of the traffic; ingressRule at index6 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-1", "sctp",
				serverPod.Status.PodIP, int32(9005), s.TimeoutConfig, false)
		})

		t.Run("Should support an 'deny-gress' policy across different protocols", func(t *testing.T) {
			// This test uses `default` baseline CNP

			/* First; let's test egress works! */
			// luna-lovegood-1 is our server pod in ravenclaw namespace
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-ravenclaw", "luna-lovegood-1", s.TimeoutConfig.GetTimeout)
			cnp := kubernetes.GetClusterNetworkPolicy(t, s.Client, "default", s.TimeoutConfig.GetTimeout)
			mutate := cnp.DeepCopy()
			// swap rules at index0 and index1 for both ingress and egress
			allowOutRule := mutate.Spec.Egress[0]
			mutate.Spec.Egress[0] = mutate.Spec.Egress[1]
			mutate.Spec.Egress[1] = allowOutRule
			allowInRule := mutate.Spec.Ingress[0]
			mutate.Spec.Ingress[0] = mutate.Spec.Ingress[1]
			mutate.Spec.Ingress[1] = allowInRule
			kubernetes.PatchClusterNetworkPolicy(t, s.Client, cnp, mutate, s.TimeoutConfig.GetTimeout)
			// harry-potter-x is our client pod in gryffindor namespace
			// ensure egress is DENIED to ravenclaw from gryffindor
			// egressRule at index0 will take precedence over egressRule at index1; thus DENY takes precedence over ALLOW since rules are ordered
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, false)
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-1", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, false)
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "sctp",
				serverPod.Status.PodIP, int32(9003), s.TimeoutConfig, false)

			/* Second; let's test ingress works! */
			// harry-potter-1 is our server pod in gryffindor namespace
			serverPod = kubernetes.GetPod(t, s.Client, "network-policy-conformance-gryffindor", "harry-potter-1", s.TimeoutConfig.GetTimeout)
			// luna-lovegood-x is our client pod in ravenclaw namespace
			// ensure ingress is DENIED from ravenclaw to gryffindor
			// ingressRule at index0 will take precedence over ingressRule at index1; thus DENY takes precedence over ALLOW since rules are ordered
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-ravenclaw", "luna-lovegood-0", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, false)
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-ravenclaw", "luna-lovegood-1", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, false)
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-ravenclaw", "luna-lovegood-1", "sctp",
				serverPod.Status.PodIP, int32(9003), s.TimeoutConfig, false)
		})

		t.Run("Should support a 'deny-gress' policy across different protocols at the specified ports", func(t *testing.T) {
			// This test uses `default` baseline CNP

			/* First; let's test egress works! */
			// draco-malfoy-0 is our server pod in slytherin namespace
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-slytherin", "draco-malfoy-0", s.TimeoutConfig.GetTimeout)
			// harry-potter-0 is our client pod in gryffindor namespace
			// ensure egress to slytherin is DENIED from gryffindor at port 80; egressRule at index3 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, false)
			// harry-potter-1 is our client pod in gryffindor namespace
			// ensure egress to slytherin is ALLOWED from gryffindor for rest of the traffic; matches no rules hence allowed
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-1", "tcp",
				serverPod.Status.PodIP, int32(8080), s.TimeoutConfig, true)
			// harry-potter-0 is our client pod in gryffindor namespace
			// ensure egress to slytherin is DENIED from gryffindor at port 53; egressRule at index3 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, false)
			// harry-potter-1 is our client pod in gryffindor namespace
			// ensure egress to slytherin is ALLOWED from gryffindor for rest of the traffic; matches no rules hence allowed
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-1", "udp",
				serverPod.Status.PodIP, int32(5353), s.TimeoutConfig, true)
			// harry-potter-0 is our client pod in gryffindor namespace
			// ensure egress to slytherin is DENIED from gryffindor at port 53; egressRule at index3 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "sctp",
				serverPod.Status.PodIP, int32(9003), s.TimeoutConfig, false)
			// harry-potter-1 is our client pod in gryffindor namespace
			// ensure egress to slytherin is ALLOWED from gryffindor for rest of the traffic; matches no rules hence allowed
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-1", "sctp",
				serverPod.Status.PodIP, int32(9005), s.TimeoutConfig, true)

			/* Second; let's test ingress works! */
			// harry-potter-0 is our server pod in gryffindor namespace
			serverPod = kubernetes.GetPod(t, s.Client, "network-policy-conformance-gryffindor", "harry-potter-0", s.TimeoutConfig.GetTimeout)
			// draco-malfoy-0 is our client pod in slytherin namespace
			// ensure ingress from slytherin is DENIED to gryffindor at port 80; ingressRule at index3 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-0", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, false)
			// draco-malfoy-1 is our client pod in slytherin namespace
			// ensure ingress from slytherin is ALLOWED to gryffindor for rest of the traffic; matches no rules hence allowed
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-1", "tcp",
				serverPod.Status.PodIP, int32(8080), s.TimeoutConfig, true)
			// draco-malfoy-0 is our client pod in slytherin namespace
			// ensure ingress from slytherin is DENIED to gryffindor at port 80; ingressRule at index3 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-0", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, false)
			// draco-malfoy-1 is our client pod in slytherin namespace
			// ensure ingress from slytherin is ALLOWED to gryffindor for rest of the traffic; matches no rules hence allowed
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-1", "udp",
				serverPod.Status.PodIP, int32(5353), s.TimeoutConfig, true)
			// draco-malfoy-0 is our client pod in slytherin namespace
			// ensure ingress from slytherin is DENIED to gryffindor at port 80; ingressRule at index3 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-0", "sctp",
				serverPod.Status.PodIP, int32(9003), s.TimeoutConfig, false)
			// draco-malfoy-1 is our client pod in slytherin namespace
			// ensure ingress from slytherin is ALLOWED to gryffindor for rest of the traffic; matches no rules hence allowed
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-slytherin", "draco-malfoy-1", "sctp",
				serverPod.Status.PodIP, int32(9005), s.TimeoutConfig, true)
		})
	},
}
