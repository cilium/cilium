// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"strings"

	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/api/v1/flow"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/source"
)

const (
	// podPrefixLbl is the value the prefix used in the label selector to
	// represent pods on the default namespace.
	podPrefixLbl = labels.LabelSourceK8sKeyPrefix + k8sConst.PodNamespaceLabel

	// podAnyPrefixLbl is the value of the prefix used in the label selector to
	// represent pods in the default namespace for any source type.
	podAnyPrefixLbl = labels.LabelSourceAnyKeyPrefix + k8sConst.PodNamespaceLabel

	// podK8SNamespaceLabelsPrefix is the prefix use in the label selector for namespace labels.
	podK8SNamespaceLabelsPrefix = labels.LabelSourceK8sKeyPrefix + k8sConst.PodNamespaceMetaLabelsPrefix
	// podAnyNamespaceLabelsPrefix is the prefix use in the label selector for namespace labels
	// for any source type.
	podAnyNamespaceLabelsPrefix = labels.LabelSourceAnyKeyPrefix + k8sConst.PodNamespaceMetaLabelsPrefix

	// clusterPrefixLbl is the prefix use in the label selector for cluster name.
	clusterPrefixLbl = labels.LabelSourceK8sKeyPrefix + k8sConst.PolicyLabelCluster

	// clusterAnyPrefixLbl is the prefix use in the label selector for cluster name
	// for any source type.
	clusterAnyPrefixLbl = labels.LabelSourceAnyKeyPrefix + k8sConst.PolicyLabelCluster

	// podInitLbl is the label used in a label selector to match on
	// initializing pods.
	podInitLbl = labels.LabelSourceReservedKeyPrefix + labels.IDNameInit

	// ResourceTypeCiliumNetworkPolicy is the resource type used for the
	// PolicyLabelDerivedFrom label
	ResourceTypeCiliumNetworkPolicy = "CiliumNetworkPolicy"

	// ResourceTypeCiliumClusterwideNetworkPolicy is the resource type used for the
	// PolicyLabelDerivedFrom label
	ResourceTypeCiliumClusterwideNetworkPolicy = "CiliumClusterwideNetworkPolicy"
)

// GetPolicyLabels returns a LabelArray for the given namespace and name.
func GetPolicyLabels(ns, name string, uid types.UID, derivedFrom string) labels.LabelArray {
	// Keep labels sorted by the key.
	labelsArr := labels.LabelArray{
		labels.NewLabel(k8sConst.PolicyLabelDerivedFrom, derivedFrom, labels.LabelSourceK8s),
		labels.NewLabel(k8sConst.PolicyLabelName, name, labels.LabelSourceK8s),
	}

	// For clusterwide policy namespace will be empty.
	if ns != "" {
		nsLabel := labels.NewLabel(k8sConst.PolicyLabelNamespace, ns, labels.LabelSourceK8s)
		labelsArr = append(labelsArr, nsLabel)
	}

	srcLabel := labels.NewLabel(k8sConst.PolicyLabelUID, string(uid), labels.LabelSourceK8s)
	return append(labelsArr, srcLabel)
}

// GetPolicyFromLabels derives and sets fields in the flow policy from the label set array.
//
// This function supports namespaced and cluster-scoped resources.
func GetPolicyFromLabels(policyLabels []string, revision uint64) *flow.Policy {
	f := &flow.Policy{
		Labels:   policyLabels,
		Revision: revision,
	}

	for _, lbl := range policyLabels {
		if lbl, isK8sLabel := strings.CutPrefix(lbl, string(source.Kubernetes)+":"); isK8sLabel {
			if key, value, found := strings.Cut(lbl, "="); found {
				switch key {
				case k8sConst.PolicyLabelName:
					f.Name = value
				case k8sConst.PolicyLabelNamespace:
					f.Namespace = value
				case k8sConst.PolicyLabelDerivedFrom:
					f.Kind = value
				default:
					if f.Kind != "" && f.Name != "" && f.Namespace != "" {
						return f
					}
				}
			}
		}
	}

	return f
}

// ParseToCiliumLabels returns all ruleLbls appended with a specific label that
// represents the given namespace and name along with a label that specifies
// these labels were derived from a CiliumNetworkPolicy.
func ParseToCiliumLabels(namespace, name string, uid types.UID, ruleLbs labels.LabelArray) labels.LabelArray {
	resourceType := ResourceTypeCiliumNetworkPolicy
	if namespace == "" {
		resourceType = ResourceTypeCiliumClusterwideNetworkPolicy
	}

	policyLbls := GetPolicyLabels(namespace, name, uid, resourceType)

	// Ensure user-defined labels have consistent source
	userLbls := make(labels.LabelArray, len(ruleLbs))
	for i, lbl := range ruleLbs {
		if lbl.Source == "" {
			// If source is empty, set it to unspec
			userLbls[i] = labels.NewLabel(lbl.Key, lbl.Value, labels.LabelSourceUnspec)
		} else {
			userLbls[i] = lbl
		}
	}

	return append(policyLbls, userLbls...).Sort()
}
