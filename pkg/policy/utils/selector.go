// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"strings"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

var (
	namespaceLabels = []string{
		k8sConst.PodNamespaceMetaLabelsPrefix,
		k8sConst.PodNamespaceLabel,
	}

	clusterLabel = labels.LabelSourceK8sKeyPrefix + k8sConst.PolicyLabelCluster
)

// EnsureNamespaceSelector ensures that there is at least some namespace constraint
// in the given endpoint selector
func EnsureNamespaceSelector(es *api.EndpointSelector, namespace string) {
	var positive, negative bool

	// Ensure there is a namespace selector.
	//
	// Namespaces can be selected by the namespace label ("io.kubernetes.pod.namespace")
	// or the special namespae label prefix ("io.cilium.k8s.namespace.labels.<XXX>")
	for _, lbl := range namespaceLabels {
		p, n := esSelects(es, lbl)
		positive = positive || p
		negative = negative || n
	}

	// Add a namespace specifier if needed.
	if !positive {
		// If there is a negative specifier, or there is no desired namespace (e.g. CCNP),
		// then just add an Exists specifier
		if negative || namespace == "" {
			es.AddMatchExpression(
				labels.LabelSourceK8sKeyPrefix+k8sConst.PodNamespaceLabel,
				slim_metav1.LabelSelectorOpExists,
				nil)
		} else {
			es.AddMatch(labels.LabelSourceK8sKeyPrefix+k8sConst.PodNamespaceLabel, namespace)
		}
	}
}

func EnsureClusterSelector(es *api.EndpointSelector, clustername string) {
	positive, negative := esSelects(es, clusterLabel)
	if !positive {
		if negative || clustername == "" {
			es.AddMatchExpression(
				labels.LabelSourceK8sKeyPrefix+k8sConst.PolicyLabelCluster,
				slim_metav1.LabelSelectorOpExists,
				nil)
		} else {
			es.AddMatch(labels.LabelSourceK8sKeyPrefix+k8sConst.PolicyLabelCluster, clustername)
		}
	}
}

// esSelects determines if a given key is selected via a label selector.
// key is a prefix.
//
// positive returns true if there is a positive selector (direct label, In, or Exists)
// negative returns true if there is a negative selector (NotIn or NotExists)
// short-cuts as soon as a positive match is found
func esSelects(es *api.EndpointSelector, key string) (positive, negative bool) {
	for _, src := range searchSources {
		wantKey := src + key
		for k := range es.MatchLabels {
			if strings.HasPrefix(k, wantKey) {
				positive = true
				return
			}
		}
		for _, expr := range es.MatchExpressions {
			if strings.HasPrefix(expr.Key, wantKey) {
				if expr.Operator == slim_metav1.LabelSelectorOpIn || expr.Operator == slim_metav1.LabelSelectorOpExists {
					positive = true
					return
				} else {
					negative = true
				}
			}
		}
	}
	return positive, negative
}

var searchSources = []string{
	"",
	labels.LabelSourceK8sKeyPrefix,
	labels.LabelSourceAnyKeyPrefix,
}
