// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"strings"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// ParseNodeLabelSelector parses a given string representation of a label selector into a metav1.LabelSelector.
// The representation is a comma-separated list of key-value pairs (key1=value1,key2=value2) that is used as MatchLabels.
// Values not matching these rules are skipped.
func ParseNodeLabelSelector(nodeLabelSelectorString string) *slim_metav1.LabelSelector {
	if nodeLabelSelectorString == "" {
		return nil
	}

	labels := map[string]string{}
	for _, v := range strings.Split(nodeLabelSelectorString, ",") {
		s := strings.Split(v, "=")
		if len(s) != 2 || len(s[0]) == 0 {
			continue
		}
		labels[s[0]] = s[1]
	}

	return &slim_metav1.LabelSelector{
		MatchLabels: labels,
	}
}
