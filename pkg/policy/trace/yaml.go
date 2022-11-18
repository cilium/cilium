// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package trace

import (
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
)

const (
	// DefaultNamespace represents the default Kubernetes namespace.
	DefaultNamespace = "default"
)

func generateLabels(namespace string, labelsMap map[string]string) []string {
	var labelsArr []string
	temp := namespace
	if temp == "" {
		temp = DefaultNamespace
	}
	labelsArr = append(labelsArr, labels.GenerateK8sLabelString(k8sConst.PodNamespaceLabel, temp))
	for k, v := range labelsMap {
		labelsArr = append(labelsArr, labels.GenerateK8sLabelString(k, v))
	}
	return labelsArr
}
