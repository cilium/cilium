// Copyright 2017-2018 Authors of Cilium
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

package utils

import (
	"fmt"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api/v3"

	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// subsysK8s is the value for logfields.LogSubsys
	subsysK8s = "k8s"
	// podPrefixLbl is the value the prefix used in the label selector to
	// represent pods on the default namespace.
	podPrefixLbl = labels.LabelSourceK8sKeyPrefix + k8sConst.PodNamespaceLabel
)

var (
	// log is the k8s package logger object.
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsysK8s)
)

// ExtractNamespace extracts the namespace of ObjectMeta.
func ExtractNamespace(np *metav1.ObjectMeta) string {
	if np.Namespace == "" {
		return v1.NamespaceDefault
	}

	return np.Namespace
}

// GetObjNamespaceName returns the object's namespace and name.
func GetObjNamespaceName(obj *metav1.ObjectMeta) string {
	return ExtractNamespace(obj) + "/" + obj.GetName()
}

// GetPolicyLabels returns a LabelArray for the given namespace and name.
func GetPolicyLabels(ns, name string) labels.LabelArray {
	return labels.ParseLabelArray(
		fmt.Sprintf("%s=%s", k8sConst.PolicyLabelName, name),
		fmt.Sprintf("%s=%s", k8sConst.PolicyLabelNamespace, ns),
	)
}

func parseToCiliumIngressRule(namespace string, inRule []v3.IngressRule) []v3.IngressRule {
	if inRule == nil {
		return nil
	}
	retRule := make([]v3.IngressRule, len(inRule))
	for i, ing := range inRule {
		retRule[i] = v3.IngressRule{}
		if ing.FromIdentities != nil {
			retRule[i].FromIdentities = &v3.IdentityRule{}

			retRule[i].FromIdentities.ToPorts = ing.FromIdentities.ToPorts.DeepCopy()

			es := v3.NewESFromK8sLabelSelector("", ing.FromIdentities.IdentitySelector.LabelSelector)
			retRule[i].FromIdentities.IdentitySelector = es
			if retRule[i].FromIdentities.IdentitySelector.MatchLabels == nil {
				retRule[i].FromIdentities.IdentitySelector.MatchLabels = map[string]string{}
			}
			// There's no need to prefixed K8s
			// prefix for reserved labels
			if retRule[i].FromIdentities.IdentitySelector.HasKeyPrefix(labels.LabelSourceReservedKeyPrefix) {
				continue
			}
			// The user can explicitly specify the namespace in the
			// FromIdentities selector. If omitted, we limit the
			// scope to the namespace the policy lives in.
			if !retRule[i].FromIdentities.IdentitySelector.HasKey(podPrefixLbl) {
				retRule[i].FromIdentities.IdentitySelector.MatchLabels[podPrefixLbl] = namespace
			}
		}

		if ing.FromRequires != nil {
			retRule[i].FromRequires = &v3.EndpointRequire{}

			retRule[i].FromRequires.IdentitySelector = make([]v3.IdentitySelector, len(ing.FromRequires.IdentitySelector))
			for i, v := range ing.FromRequires.IdentitySelector {
				es := v3.NewESFromK8sLabelSelector("", v.LabelSelector)
				if es.MatchLabels == nil {
					es.MatchLabels = map[string]string{}
				}
				// The user can explicitly specify the namespace in the
				// FromIdentities selector. If omitted, we limit the
				// scope to the namespace the policy lives in.
				if _, ok := es.MatchLabels[podPrefixLbl]; !ok {
					es.MatchLabels[podPrefixLbl] = namespace
				}
				retRule[i].FromRequires.IdentitySelector[i] = es
			}
		}

		retRule[i].FromEntities = ing.FromEntities.DeepCopy()

		retRule[i].FromCIDRs = ing.FromCIDRs.DeepCopy()
	}

	return retRule
}

func parseToCiliumEgressRule(namespace string, inRule []v3.EgressRule) []v3.EgressRule {
	if inRule == nil {
		return nil
	}
	retRule := make([]v3.EgressRule, len(inRule))
	for i, eg := range inRule {
		retRule[i] = v3.EgressRule{}
		if eg.ToIdentities != nil {
			retRule[i].ToIdentities = &v3.IdentityRule{}

			retRule[i].ToIdentities.ToPorts = eg.ToIdentities.ToPorts.DeepCopy()

			es := v3.NewESFromK8sLabelSelector("", eg.ToIdentities.IdentitySelector.LabelSelector)
			retRule[i].ToIdentities.IdentitySelector = es
			if retRule[i].ToIdentities.IdentitySelector.MatchLabels == nil {
				retRule[i].ToIdentities.IdentitySelector.MatchLabels = map[string]string{}
			}
			// There's no need to prefixed K8s
			// prefix for reserved labels
			if retRule[i].ToIdentities.IdentitySelector.HasKeyPrefix(labels.LabelSourceReservedKeyPrefix) {
				continue
			}
			// The user can explicitly specify the namespace in the
			// ToEndpoints selector. If omitted, we limit the
			// scope to the namespace the policy lives in.
			if !retRule[i].ToIdentities.IdentitySelector.HasKey(podPrefixLbl) {
				retRule[i].ToIdentities.IdentitySelector.MatchLabels[podPrefixLbl] = namespace
			}
		}

		if eg.ToRequires != nil {
			retRule[i].ToRequires = &v3.EndpointRequire{}

			retRule[i].ToRequires.IdentitySelector = make([]v3.IdentitySelector, len(eg.ToRequires.IdentitySelector))
			for i, v := range eg.ToRequires.IdentitySelector {
				es := v3.NewESFromK8sLabelSelector("", v.LabelSelector)
				if es.MatchLabels == nil {
					es.MatchLabels = map[string]string{}
				}
				// The user can explicitly specify the namespace in the
				// ToEndpoints selector. If omitted, we limit the
				// scope to the namespace the policy lives in.
				if _, ok := es.MatchLabels[podPrefixLbl]; !ok {
					es.MatchLabels[podPrefixLbl] = namespace
				}

				retRule[i].ToRequires.IdentitySelector[i] = es
			}
		}

		retRule[i].ToEntities = eg.ToEntities.DeepCopy()

		retRule[i].ToCIDRs = eg.ToCIDRs.DeepCopy()

		retRule[i].ToServices = eg.ToServices.DeepCopy()
	}

	return retRule
}

// ParseToCiliumRule returns a v3.Rule with all the labels parsed into cilium
// labels.
func ParseToCiliumRule(namespace, name string, r *v3.Rule) *v3.Rule {
	retRule := &v3.Rule{}
	if r.EndpointSelector.LabelSelector != nil {
		retRule.EndpointSelector = v3.NewESFromK8sLabelSelector("", r.EndpointSelector.LabelSelector)
		// The PodSelector should only reflect to the same namespace
		// the policy is being stored, thus we add the namespace to
		// the MatchLabels map.
		if retRule.EndpointSelector.LabelSelector.MatchLabels == nil {
			retRule.EndpointSelector.LabelSelector.MatchLabels = map[string]string{}
		}

		userNamespace, ok := retRule.EndpointSelector.LabelSelector.MatchLabels[podPrefixLbl]
		if ok && userNamespace != namespace {
			log.WithFields(logrus.Fields{
				logfields.K8sNamespace:              namespace,
				logfields.CiliumNetworkPolicyName:   name,
				logfields.K8sNamespace + ".illegal": userNamespace,
			}).Warn("CiliumNetworkPolicy contains illegal namespace match in EndpointSelector." +
				" EndpointSelector always applies in namespace of the policy resource, removing illegal namespace match'.")
		}
		retRule.EndpointSelector.LabelSelector.MatchLabels[podPrefixLbl] = namespace
	}

	retRule.Ingress = parseToCiliumIngressRule(namespace, r.Ingress)
	retRule.Egress = parseToCiliumEgressRule(namespace, r.Egress)

	policyLbls := GetPolicyLabels(namespace, name)
	if retRule.Labels == nil {
		retRule.Labels = make(labels.LabelArray, 0, len(policyLbls))
	}
	retRule.Labels = append(retRule.Labels, policyLbls...)

	retRule.Description = r.Description

	return retRule
}
