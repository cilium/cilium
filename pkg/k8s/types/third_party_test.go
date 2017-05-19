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
        ]
    }
}`)
)

func (s *K8sSuite) TestParseThirdParty(c *C) {
	policyRule := &CiliumNetworkPolicy{
		Metadata: metav1.ObjectMeta{
			Name: "rule1",
		},
		Spec: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseLabel("role=backend")),
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							labels.ParseLabel("role=frontend"),
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
		},
	}

	rules, err := policyRule.Parse()
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)

	cnpl := CiliumNetworkPolicy{}
	err = json.Unmarshal(ciliumRule, &cnpl)
	c.Assert(err, IsNil)
	c.Assert(cnpl, DeepEquals, *policyRule)
}
