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
	"testing"

	api "sigs.k8s.io/network-policy-api/apis/v1alpha2"
	"sigs.k8s.io/network-policy-api/conformance/utils/kubernetes"
	"sigs.k8s.io/network-policy-api/conformance/utils/suite"
)

var CNPAdminTierIngressNamedPort = suite.ConformanceTest{
	ShortName:   "CNPAdminTierIngressNamedPort",
	Description: "Tests support for ingress traffic on a named port using cluster network policy API based on a server and client model",
	Features: []suite.SupportedFeature{
		suite.SupportClusterNetworkPolicy,
		suite.SupportClusterNetworkPolicyNamedPorts,
	},
	Manifests: []string{"base/admin_tier/standard-ingress-udp-rules.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {

		t.Run("Should support an 'allow-ingress' policy for named port", func(t *testing.T) {
			// This test uses `ingress-udp` admin CNP
			// cedric-diggory-1 is our server pod in hufflepuff namespace
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-hufflepuff", "cedric-diggory-1", s.TimeoutConfig.GetTimeout)
			cnp := kubernetes.GetClusterNetworkPolicy(t, s.Client, "ingress-udp", s.TimeoutConfig.GetTimeout)
			mutate := cnp.DeepCopy()
			dnsPortRule := mutate.DeepCopy().Spec.Ingress[5]
			dnsPort := "dns"
			// rewrite the udp port 53 rule as named port rule
			dnsPortRule.Protocols = []api.ClusterNetworkPolicyProtocol{
				{
					DestinationNamedPort: dnsPort,
				},
			}
			mutate.Spec.Ingress[5] = dnsPortRule
			kubernetes.PatchClusterNetworkPolicy(t, s.Client, cnp, mutate, s.TimeoutConfig.GetTimeout)
			// harry-potter-0 is our client pod in gryffindor namespace
			// ensure ingress is ALLOWED from gryffindor to hufflepuff at the dns port, which is defined as UDP at port 53 in pod spec
			// modified ingressRule at index5 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "udp",
				serverPod.Status.PodIP, int32(53), s.TimeoutConfig, true)
			// harry-potter-1 is our client pod in gryfindor namespace
			// ensure ingress is DENIED from gryffindor to hufflepuff for rest of the traffic; ingressRule at index6 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-1", "udp",
				serverPod.Status.PodIP, int32(5353), s.TimeoutConfig, false)
		})
	},
}
