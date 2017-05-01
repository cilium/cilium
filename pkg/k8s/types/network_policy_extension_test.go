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

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/ghodss/yaml"
	. "gopkg.in/check.v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

func (s *K8sSuite) TestParseNetworkPolicyExtension(c *C) {
	yamlEx := `---
apiVersion: extensions/v1beta1
kind: NetworkPolicy
metadata:
  name: guestbook-web
  annotations:
   cilium-policy: |
    {
      "ingress": [
        {
          "from": [
            {
              "ciliumSelector": {
                "matchLabels": {
                  "io.cilium.reserved": "world"
                }
              }
            }
          ]
        }
      ]
    }
spec:
  podSelector:
    matchLabels:
      k8s-app.guestbook: web
  ingress:
  - from:
    - podSelector: {}
    ports:
    - protocol: TCP
      port: 3000
`

	np := v1beta1.NetworkPolicy{}
	jsonBytes, err := yaml.YAMLToJSON([]byte(yamlEx))
	c.Assert(err, IsNil)

	err = json.Unmarshal(jsonBytes, &np)
	c.Assert(err, IsNil)

	parent, node, err := ParseNetworkPolicy(&np)
	c.Assert(err, IsNil)
	c.Assert(parent, Equals, k8s.DefaultPolicyParentPath)
	c.Assert(node, Not(IsNil))

	t := policy.NewTree()
	t.Add(parent, node)

	ctx := policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(policy.JoinPath(k8s.PodNamespaceMetaLabels, "component"), "redis", k8s.LabelSource),
			labels.NewLabel(policy.JoinPath(k8s.PodNamespaceMetaLabels, "tier"), "cache", k8s.LabelSource),
		},
		DPorts: []*models.Port{
			{
				Port:     3000,
				Protocol: "tcp",
			},
		},
		To: labels.LabelArray{
			labels.NewLabel(k8s.PodNamespaceLabelPrefix, "default", k8s.LabelSource),
			labels.NewLabel("k8s-app.guestbook", "web", k8s.LabelSource),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	decision := t.AllowsRLocked(&ctx)
	// Should be DENY since they don't belong in the same namespace.
	c.Assert(decision, Equals, api.DENY)

	ctx.From = append(ctx.From, labels.NewLabel(k8s.PodNamespaceLabelPrefix, "default", k8s.LabelSource))
	decision = t.AllowsRLocked(&ctx)
	l4decision := t.AllowsL4RLocked(&ctx)
	// Should be ACCEPT since they belong in the same namespace.
	c.Assert(decision, Equals, api.ACCEPT)
	c.Assert(l4decision, Equals, api.ACCEPT)

	ctx.From = labels.LabelArray{
		labels.NewLabel("world", "", common.ReservedLabelSource),
	}

	decision = t.AllowsRLocked(&ctx)
	l4decision = t.AllowsL4RLocked(&ctx)
	// Should be ACCEPT since reserved:world is in the list of accepted sources.
	c.Assert(decision, Equals, api.ACCEPT)
	c.Assert(l4decision, Equals, api.ACCEPT)
}
