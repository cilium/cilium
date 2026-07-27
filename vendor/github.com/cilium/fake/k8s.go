// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"fmt"
	"math/rand"
)

// K8sLabels generates a random set of Kubernetes labels.
func K8sLabels() []string {
	var l []string
	for _, name := range labels {
		if rand.Intn(2) == 0 { // 50% chance of picking up this label
			l = append(l, name+"="+App())
		}
	}
	return l
}

// K8sNamespace generates a random Kubernetes namespace name.
func K8sNamespace() string {
	if rand.Intn(2) == 0 {
		return namespaces[rand.Intn(len(namespaces))]
	}
	return fmt.Sprintf("%s-%s", App(), DeploymentTier())
}

// K8sNodeName generates a random Kubernetes node name.
func K8sNodeName() string {
	return fmt.Sprintf(
		"%s-%s",
		Adjective(),
		Noun(),
	)
}

// K8sPodName generates a random Kubernetes pod name.
func K8sPodName() string {
	return fmt.Sprintf(
		"%s-%s",
		App(),
		AlphaNum(5),
	)
}
