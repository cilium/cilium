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

func init() {
	ConformanceTests = append(ConformanceTests,
		CNPAdminTierEgressNamedPort,
		CNPAdminTierEgressNodePeers,
	)
}

var CNPAdminTierEgressNamedPort = suite.ConformanceTest{
	ShortName:   "CNPAdminTierEgressNamedPort",
	Description: "Tests support for egress traffic on a named port using cluster network policy API based on a server and client model",
	Features: []suite.SupportedFeature{
		suite.SupportClusterNetworkPolicy,
		suite.SupportClusterNetworkPolicyNamedPorts,
	},
	Manifests: []string{"base/admin_tier/standard-egress-tcp-rules.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {

		t.Run("Should support an 'allow-egress' policy for named port", func(t *testing.T) {
			// This test uses `egress-tcp` admin CNP
			// cedric-diggory-1 is our server pod in hufflepuff namespace
			serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-hufflepuff", "cedric-diggory-1", s.TimeoutConfig.GetTimeout)
			cnp := kubernetes.GetClusterNetworkPolicy(t, s.Client, "egress-tcp", s.TimeoutConfig.GetTimeout)
			mutate := cnp.DeepCopy()
			namedPortRule := mutate.Spec.Egress[5]
			webPort := "web"
			// replace the tcp port 8080 rule as named port rule which translate to tcp port 80 instead
			namedPortRule.Protocols = []api.ClusterNetworkPolicyProtocol{
				{
					DestinationNamedPort: webPort,
				},
			}
			mutate.Spec.Egress[5] = namedPortRule
			kubernetes.PatchClusterNetworkPolicy(t, s.Client, cnp, mutate, s.TimeoutConfig.GetTimeout)
			// harry-potter-0 is our client pod in gryffindor namespace
			// ensure egress is ALLOWED to hufflepuff from gryffindor at the web port, which is defined as TCP at port 80 in pod spec
			// egressRule at index5 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-0", "tcp",
				serverPod.Status.PodIP, int32(80), s.TimeoutConfig, true)
			// harry-potter-1 is our client pod in gryffindor namespace
			// ensure egress is DENIED to hufflepuff from gryffindor for rest of the traffic; egressRule at index6 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-1", "tcp",
				serverPod.Status.PodIP, int32(8080), s.TimeoutConfig, false)
		})
	},
}

var CNPAdminTierEgressNodePeers = suite.ConformanceTest{
	ShortName:   "CNPAdminTierEgressNodePeers",
	Description: "Tests support for egress traffic to node peers using cluster network policy API based on a server and client model",
	Features: []suite.SupportedFeature{
		suite.SupportClusterNetworkPolicy,
		suite.SupportClusterNetworkPolicyEgressNodePeers,
	},
	Manifests: []string{"base/admin_tier/experimental-egress-selector-rules.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		// This test uses `node-and-cidr-as-peers-example` admin CNP
		// centaur-1 is our server host-networked pod in forbidden-forrest namespace
		serverPod := kubernetes.GetPod(t, s.Client, "network-policy-conformance-forbidden-forrest", "centaur-1", s.TimeoutConfig.GetTimeout)
		t.Run("Should support an 'allow-egress' rule policy for egress-node-peer", func(t *testing.T) {
			// harry-potter-1 is our client pod in gryffindor namespace
			// ensure egress is ALLOWED to forbidden-forrest from gryffindor at the s.HostNetworkPorts[0] TCP port
			// egressRule at index0 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-1", "tcp",
				serverPod.Status.PodIP, int32(s.HostNetworkPorts[0]), s.TimeoutConfig, true)
		})
		t.Run("Should support a 'pass-egress' rule policy for egress-node-peer", func(t *testing.T) {
			// harry-potter-1 is our client pod in gryffindor namespace
			// ensure egress is PASSED to forbidden-forrest from gryffindor at the s.HostNetworkPorts[2] UDP port
			// egressRule at index1 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-1", "udp",
				serverPod.Status.PodIP, int32(s.HostNetworkPorts[2]), s.TimeoutConfig, true) // Pass rule at index2 takes effect
		})
		t.Run("Should support a 'deny-egress' rule policy for egress-node-peer", func(t *testing.T) {
			// harry-potter-1 is our client pod in gryffindor namespace
			// ensure egress is DENIED to rest of the nodes from gryffindor; egressRule at index2 should take effect
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-1", "tcp",
				serverPod.Status.PodIP, int32(s.HostNetworkPorts[1]), s.TimeoutConfig, false)
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-1", "udp",
				serverPod.Status.PodIP, int32(s.HostNetworkPorts[4]), s.TimeoutConfig, false)
			kubernetes.PokeServer(t, s.ClientSet, &s.KubeConfig, "network-policy-conformance-gryffindor", "harry-potter-1", "sctp",
				serverPod.Status.PodIP, int32(s.HostNetworkPorts[6]), s.TimeoutConfig, false)
		})
	},
}
