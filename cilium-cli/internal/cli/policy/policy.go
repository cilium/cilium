// Copyright 2020 Authors of Cilium
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

package policy

import (
	"context"
	"strings"

	"github.com/cilium/cilium-cli/internal/k8s"

	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Policy struct {
	NumberSpecs   int
	SelectedPods  int
	NumberIngress int
	NumberEgress  int
	ContainsL4    bool
	ContainsDNS   bool
}

func (p Policy) Summary() string {
	elements := []string{}
	if p.ContainsL4 {
		elements = append(elements, "L4")
	}

	return strings.Join(elements, ",")
}

type PolicyMap map[string]Policy

type Policies struct {
	PolicyMap PolicyMap
}

func newPolicies() *Policies {
	return &Policies{
		PolicyMap: PolicyMap{},
	}
}

type policiesCollector struct {
	client *k8s.Client
}

type ListPoliciesParams struct {
	Namespace string
	Selects   string
}

func ListPolicies(c *k8s.Client, params ListPoliciesParams) (*Policies, error) {
	s := policiesCollector{
		client: c,
	}

	return s.listPolicies(context.TODO(), params)
}

func podLabels(pod corev1.Pod, namespace string) labels.LabelArray {
	l := pod.Labels
	// TODO
	//for k, v := range k8sNs.GetLabels() {
	//k8sLabels[policy.JoinPath(ciliumio.PodNamespaceMetaLabels, k)] = v
	//}

	l[ciliumio.PodNamespaceLabel] = namespace

	if pod.Spec.ServiceAccountName != "" {
		l[ciliumio.PolicyLabelServiceAccount] = pod.Spec.ServiceAccountName
	} else {
		delete(l, ciliumio.PolicyLabelServiceAccount)
	}

	// TODO
	// labels[ciliumio.PolicyLabelCluster] = option.Config.ClusterName

	return labels.Map2Labels(l, labels.LabelSourceK8s).LabelArray()
}

func (p *policiesCollector) listPolicies(ctx context.Context, params ListPoliciesParams) (*Policies, error) {
	policies := newPolicies()

	cnps, err := p.client.CiliumClientset.CiliumV2().CiliumNetworkPolicies(params.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	pods, err := p.client.Clientset.CoreV1().Pods(params.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var selectLabels labels.LabelArray
	if params.Selects != "" {
		selectLabels = []labels.Label{labels.ParseSelectLabel(params.Selects)}
	}

nextCNP:
	for _, cnp := range cnps.Items {
		policy := Policy{}

		rules, err := cnp.Parse()
		if err != nil {
			return nil, err
		}

		for _, r := range rules {
			if params.Selects != "" {
				if !r.EndpointSelector.Matches(selectLabels) {
					continue nextCNP
				}
			}

			policy.NumberSpecs++
			for _, pod := range pods.Items {
				podLabels := podLabels(pod, pod.Namespace)
				if r.EndpointSelector.Matches(podLabels) {
					policy.SelectedPods++
				}
			}

			policy.NumberIngress += len(r.Ingress)
			policy.NumberEgress += len(r.Egress)

			for _, ingress := range r.Ingress {
				if len(ingress.ToPorts) > 0 {
					policy.ContainsL4 = true
				}
			}

			for _, egress := range r.Egress {
				if len(egress.ToPorts) > 0 {
					policy.ContainsL4 = true
				}
			}
		}

		policies.PolicyMap["cnp"+"/"+cnp.Namespace+"/"+cnp.Name] = policy
	}

	return policies, nil
}
