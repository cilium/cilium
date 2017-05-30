// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package k8s

import (
	"encoding/json"
	"fmt"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	ciliumRule = []byte(`{
    "metadata": {
        "name": "rule1"
    },
    "spec": {
        "endpointSelector": {
            "matchLabels": {
                "role": "backend"
            }
        },
        "ingress": [
            {
                "fromEndpoints": [
                    {
                        "matchLabels": {
                            "role": "frontend"
                        }
                    },
                    {
                        "matchLabels": {
                            "reserved:world": ""
                        }
                    }
                ],
                "toPorts": [
                    {
                        "ports": [
                            {
                                "port": "80",
                                "protocol": "TCP"
                            }
                        ],
                        "rules": {
                            "http": [
                                {
                                    "path": "/public",
                                    "method": "GET"
                                }
                            ]
                        }
                    }
                ]
            }
        ],
        "egress": [
            {
                "toPorts": [
                    {
                        "ports": [
                            {
                                "port": "80",
                                "protocol": "TCP"
                            }
                        ],
                        "rules": {
                            "http": [
                                {
                                    "path": "/public",
                                    "method": "GET"
                                }
                            ]
                        }
                    }
                ],
                "toCIDR": [
                    {
                        "ip": "10.0.0.1"
                    }
                ]
            }
        ]
    }
}`)
)

func (s *K8sSuite) TestParseThirdParty(c *C) {
	expectedPolicyRule := &CiliumNetworkPolicy{
		Metadata: metav1.ObjectMeta{
			Name: "rule1",
		},
		Spec: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseLabel("any:role=backend")),
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							labels.ParseLabel("any:role=frontend"),
						),
						api.NewESFromLabels(
							labels.ParseLabel("reserved:world"),
						),
					},
					ToPorts: []api.PortRule{
						{
							Ports: []api.PortProtocol{{Port: "80", Protocol: "TCP"}},
							Rules: &api.L7Rules{HTTP: []api.PortRuleHTTP{{Path: "/public", Method: "GET"}}},
						},
					},
				},
			},
			Egress: []api.EgressRule{
				{
					ToPorts: []api.PortRule{
						{
							Ports: []api.PortProtocol{{Port: "80", Protocol: "TCP"}},
							Rules: &api.L7Rules{HTTP: []api.PortRuleHTTP{{Path: "/public", Method: "GET"}}},
						},
					},
					ToCIDR: []api.CIDR{
						{
							IP: "10.0.0.1",
						},
					},
				},
			},
		},
	}

	expectedSpecRule := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseLabel("any:role=backend"), labels.ParseLabel("k8s:"+k8s.PodNamespaceLabel+"=default")),
		Ingress: []api.IngressRule{
			{
				FromEndpoints: []api.EndpointSelector{
					api.NewESFromLabels(
						labels.ParseLabel("any:role=frontend"),
						labels.ParseLabel("k8s:"+k8s.PodNamespaceLabel+"=default"),
					),
					api.NewESFromLabels(
						labels.ParseLabel("reserved:world"),
					),
				},
				ToPorts: []api.PortRule{
					{
						Ports: []api.PortProtocol{{Port: "80", Protocol: "TCP"}},
						Rules: &api.L7Rules{HTTP: []api.PortRuleHTTP{{Path: "/public", Method: "GET"}}},
					},
				},
			},
		},
		Egress: []api.EgressRule{
			{
				ToPorts: []api.PortRule{
					{
						Ports: []api.PortProtocol{{Port: "80", Protocol: "TCP"}},
						Rules: &api.L7Rules{HTTP: []api.PortRuleHTTP{{Path: "/public", Method: "GET"}}},
					},
				},
				ToCIDR: []api.CIDR{
					{
						IP: "10.0.0.1",
					},
				},
			},
		},
		Labels: labels.ParseLabelArray(fmt.Sprintf("%s=%s", k8s.PolicyLabelName, "rule1")),
	}

	rules, err := expectedPolicyRule.Parse()
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)
	c.Assert(*rules[0], DeepEquals, expectedSpecRule)

	cnpl := CiliumNetworkPolicy{}
	err = json.Unmarshal(ciliumRule, &cnpl)
	c.Assert(err, IsNil)
	c.Assert(cnpl, DeepEquals, *expectedPolicyRule)
}
