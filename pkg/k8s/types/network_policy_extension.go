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

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

// NetworkPolicyExtensionSpec is an extension for the kubernetes network policy.
// Contains a array of ingress rules that will be merged into the standard
// kubernetes network policy ingress rules.
type NetworkPolicyExtensionSpec struct {
	Ingress []NetworkPolicyIngressRule `json:"ingress"`
}

// NetworkPolicyIngressRule contains a slice of NetworkPolicyPeers;
type NetworkPolicyIngressRule struct {
	From []NetworkPolicyPeer `json:"from"`
}

// UnmarshalJSON unmarshals the byte array into the receivers'
// NetworkPolicyIngressRule.
func (n *NetworkPolicyIngressRule) UnmarshalJSON(b []byte) error {
	var objMap map[string]*json.RawMessage
	err := json.Unmarshal(b, &objMap)
	if err != nil {
		return err
	}

	var netPolicyPeers []NetworkPolicyPeer
	if objMap["from"] != nil {
		err = json.Unmarshal(*objMap["from"], &netPolicyPeers)
		if err != nil {
			return err
		}
	} else {
		netPolicyPeers = []NetworkPolicyPeer{}
	}
	n.From = netPolicyPeers

	return nil
}

// ParseNetworkPolicyExtension unmarshals the NetworkPolicyExtensionSpec writen
// in the cilium annotation and merges with the rules of the given policy node.
func ParseNetworkPolicyExtension(np *v1beta1.NetworkPolicy, pn *policy.Node) error {
	ciliumPolicyJSON := np.Annotations[k8s.AnnotationCiliumPolicy]
	npes := NetworkPolicyExtensionSpec{}
	if err := json.Unmarshal([]byte(ciliumPolicyJSON), &npes); err != nil {
		return err
	}
	allowRules := []*policy.AllowRule{}
	for _, ing := range npes.Ingress {
		for _, rule := range ing.From {
			ar := &policy.AllowRule{
				Action:        api.ALWAYS_ACCEPT,
				MatchSelector: rule.CiliumSelector,
			}
			allowRules = append(allowRules, ar)
		}
	}
	if len(allowRules) > 0 {
		pn.Rules = append(pn.Rules, &policy.RuleConsumers{
			RuleBase: policy.RuleBase{CoverageSelector: &np.Spec.PodSelector},
			Allow:    allowRules,
		})
	}
	return nil
}

// NetworkPolicyPeer contains the cilium selector which will be used for
// reserved cilium labels.
type NetworkPolicyPeer struct {
	CiliumSelector *metav1.LabelSelector `json:"ciliumSelector,omitempty"`
}
