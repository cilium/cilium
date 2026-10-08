// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import (
	k8sLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
)

// K8sLabelArray is a custom type for LabelArray that implements
// "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels".Labels
//
// This type assumes the submitted key for check is in the form `source.key`,
// instead of the cilium representation of `source:key`.
type K8sLabelArray []Label

var _ k8sLabels.Labels = K8sLabelArray{}

func (ls K8sLabelArray) Has(key string) bool {
	_, exists := ls.Lookup(key)
	return exists
}

func (ls K8sLabelArray) Get(key string) string {
	value, _ := ls.Lookup(key)
	return value
}

func (ls K8sLabelArray) Lookup(label string) (value string, exists bool) {
	keyLabel := ParseSelectDotLabel(label)
	return ls.lookupLabel(&keyLabel)
}

func (ls K8sLabelArray) lookupLabel(keyLabel *Label) (value string, exists bool) {
	for i := range ls {
		if ls[i].HasKey(keyLabel) {
			return ls[i].Value, true
		}
	}
	return "", false
}

// ParseSelectDotLabel returns a selecting label representation of the given
// string. Unlike ParseSelectLabel it expects the source separator to be '.'.
func ParseSelectDotLabel(str string) Label {
	return parseSelectLabel(str, k8sSourceDelimiter)
}

// ParseK8sLabelArrayFromArray converts an array of strings as labels and returns the
// K8s LabelArray representation.
func ParseK8sLabelArrayFromArray(labels []string) K8sLabelArray {
	return K8sLabelArray(ParseLabelArrayFromArray(labels))
}
