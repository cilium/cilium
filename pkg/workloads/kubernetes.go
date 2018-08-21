// Copyright 2018 Authors of Cilium
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

package workloads

import (
	"github.com/cilium/cilium/pkg/k8s"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sDockerLbls "k8s.io/kubernetes/pkg/kubelet/types"
)

// fetchK8sLabels returns the kubernetes labels from the given container labels
func fetchK8sLabels(containerLbls map[string]string) (map[string]string, error) {
	if !k8s.IsEnabled() {
		return nil, nil
	}
	podName := k8sDockerLbls.GetPodName(containerLbls)
	if podName == "" {
		return nil, nil
	}
	ns := k8sDockerLbls.GetPodNamespace(containerLbls)
	if ns == "" {
		ns = "default"
	}
	log.WithFields(logrus.Fields{
		logfields.K8sNamespace: ns,
		logfields.K8sPodName:   podName,
	}).Debug("Connecting to k8s to retrieve labels for pod in ns")

	result, err := k8s.Client().CoreV1().Pods(ns).Get(podName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	// Also get all labels from the namespace where the pod is running
	k8sNs, err := k8s.Client().CoreV1().Namespaces().Get(ns, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	k8sLabels := result.GetLabels()
	if k8sLabels == nil {
		k8sLabels = map[string]string{}
	}
	for k, v := range k8sNs.GetLabels() {
		k8sLabels[policy.JoinPath(k8sConst.PodNamespaceMetaLabels, k)] = v
	}
	k8sLabels[k8sConst.PodNamespaceLabel] = ns
	return k8sLabels, nil
}
