// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identities

import (
	"context"
	"fmt"
	"testing"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/fqdn/re"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	operatorOption "github.com/cilium/cilium/operator/option"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/test/controlplane"
	"github.com/cilium/cilium/test/controlplane/suite"
)

var (
	dummyPolicy = &v2.CiliumNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "cilium.io/v2",
			Kind:       "CiliumNetworkPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "fqdn-proxy-policy",
		},
		Specs: api.Rules{
			{
				Description: "",
				Egress: []api.EgressRule{
					{
						ToPorts: api.PortRules{
							{
								Ports: []api.PortProtocol{
									{
										Port:     "53",
										Protocol: "ANY",
									},
								},
								Rules: &api.L7Rules{
									DNS: []api.PortRuleDNS{
										{
											MatchPattern: "*",
										},
									},
								},
							},
						},
						ToFQDNs: api.FQDNSelectorSlice{
							{
								MatchPattern: "vagrant-cache.ci.cilium.io",
							},
						},
					},
				},
				EndpointSelector: api.EndpointSelector{
					LabelSelector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"id": "app2",
						},
						MatchExpressions: []slim_metav1.LabelSelectorRequirement{},
					},
				},
			},
			{
				Egress: []api.EgressRule{
					{
						ToPorts: api.PortRules{
							{
								Ports: []api.PortProtocol{
									{
										Port:     "53",
										Protocol: "ANY",
									},
								},
								Rules: &api.L7Rules{
									DNS: []api.PortRuleDNS{
										{
											MatchPattern: "*",
										},
									},
								},
							},
						},
						ToFQDNs: api.FQDNSelectorSlice{
							{
								MatchPattern: "jenkins.cilium.io",
							},
						},
					},
				},
				EndpointSelector: api.EndpointSelector{
					LabelSelector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"id": "app3",
						},
						MatchExpressions: []slim_metav1.LabelSelectorRequirement{},
					},
				},
			},
		},
	}

	dummyPod = &v2.CiliumEndpoint{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "cilium.io/v2",
			Kind:       "CiliumEndpoint",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "pod-1",
			Labels: map[string]string{
				"": "",
			},
		},
		Status: v2.EndpointStatus{
			ID: 201,
			Identity: &v2.EndpointIdentity{
				ID:     1337,
				Labels: []string{},
			},
			Networking: &v2.EndpointNetworking{
				Addressing: []*v2.AddressPair{
					{
						IPV4: "",
					},
				},
			},
			State: "ready",
		}}
)

func applyDummyPolicy(test *suite.ControlPlaneTest) error {
	test.UpdateObjects(dummyPolicy)

	if _, err := test.Get(
		schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"},
		"",
		dummyPolicy.Name,
	); err != nil {
		return fmt.Errorf("unable to find CiliumNetworkPolicy %q: %w", dummyPolicy.Name, err)
	}

	return nil
}

func applyDummyEndpoint(test *suite.ControlPlaneTest) error {
	name := "pod-1"
	if _, err := test.Get(
		schema.GroupVersionResource{Group: "core", Version: "v1", Resource: "pods"},
		"default",
		name,
	); err != nil {
		return fmt.Errorf("unable to find pod %q: %w", name, err)
	}

	_, _, err := test.Daemon.CreateEndpoint(context.TODO(), test.Daemon, &models.EndpointChangeRequest{
		Addressing: &models.AddressPair{
			IPV4: "10.1.1.101",
		},
		ContainerID:   "container-id-1",
		ContainerName: "container-name-1",
		K8sPodName:    name,
		K8sNamespace:  "default",
		Labels:        []string{},
	})
	return err
}

func validateFQDNIdentities(test *suite.ControlPlaneTest) error {
	fmt.Printf("chris endpoints=%v\n", test.Daemon.GetEndpoints())
	return nil
}

func init() {
	suite.AddTestCase("FQDN", func(t *testing.T) {
		k8sVersions := controlplane.K8sVersions()
		// We only need to test the last k8s version
		test := suite.NewControlPlaneTest(t, "identity-control-plane", k8sVersions[len(k8sVersions)-1])

		defer test.StopAgent()
		defer test.StopOperator()

		modConfig := func(dc *option.DaemonConfig, _ *operatorOption.OperatorConfig) {
			dc.EnableL7Proxy = true

			re.InitRegexCompileLRU(defaults.FQDNRegexCompileLRUSize)
		}
		test.
			UpdateObjects(initialObjects...).
			SetupEnvironment(modConfig).
			StartAgent().
			StartOperator().
			Execute(func() error { return applyDummyPolicy(test) }).
			Execute(func() error { return applyDummyEndpoint(test) }).
			Eventually(func() error { return validateFQDNIdentities(test) })
	})
}
