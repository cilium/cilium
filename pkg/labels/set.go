// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

// LabelMatcher allows lookup of a Label in a set implementing the interface.
type LabelMatcher interface {
	LookupLabel(key *Label) (value string, exists bool)
}

// K8sSet can be converted directly from
// github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels.K8sSet.
// Implements LabelMatcher.
// Map keys are treated as Label with "k8s" source.
type K8sSet map[string]string

func (s K8sSet) LookupLabel(l *Label) (value string, exists bool) {
	if l.IsAnySource() || l.Source == LabelSourceK8s {
		value, exists = s[l.Key]
	}
	return value, exists
}
