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

	api "sigs.k8s.io/network-policy-api/apis/v1alpha2"
	"sigs.k8s.io/network-policy-api/conformance/utils/kubernetes"
	"sigs.k8s.io/network-policy-api/conformance/utils/suite"
)

func init() {
	ConformanceTests = append(ConformanceTests,
		CNPBaselineTierIngressNamedPort,
	)
}

var CNPBaselineTierIngressNamedPort = suite.ConformanceTest{
	ShortName:   "CNPBaselineTierIngressNamedPort",
	Description: "Tests support for ingress traffic on a named port using baseline cluster network policy API based on a server and client model",
	Features: []suite.SupportedFeature{
		suite.SupportClusterNetworkPolicy,
		suite.SupportClusterNetworkPolicyNamedPorts,
	},
	Manifests: []string{"base/baseline_tier/standard-ingress-tcp-rules.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {

		t.Run("Should support an 'allow-ingress' policy for named port", func(t *testing.T) {
			// This test uses `default` baseline CNP
			// harry-potter-1 is our server pod in gryffindor namespace
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-gryffindor", "harry-potter-1", s.TimeoutConfig.GetTimeout)
			cnp := kubernetes.GetClusterNetworkPolicy(t, s.Client, "default", s.TimeoutConfig.GetTimeout)
			mutate := cnp.DeepCopy()
			namedPortRule := mutate.Spec.Ingress[3]
			webPort := "web"
			// rewrite the tcp port 80 rule as named port rule
			namedPortRule.Protocols = []api.ClusterNetworkPolicyProtocol{
				{
					DestinationNamedPort: webPort,
				},
			}
			mutate.Spec.Ingress[3] = namedPortRule
			kubernetes.PatchClusterNetworkPolicy(t, s.Client, cnp, mutate, s.TimeoutConfig.GetTimeout)
			// cedric-diggory-0 is our client pod in hufflepuff namespace
			// ensure ingress is ALLOWED from hufflepuff to gryffindor at at the web port, which is defined as TCP at port 80 in pod spec
			// ingressRule at index3 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-0", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, true)
			// cedric-diggory-1 is our client pod in hufflepuff namespace
			// ensure ingress is DENIED from hufflepuff to gryffindor for rest of the traffic; ingressRule at index4 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-hufflepuff", "cedric-diggory-1", "tcp",
				serverPod.Status.PodIP, int32(8080), s.TimeoutConfig, false)
		})
	},
}
