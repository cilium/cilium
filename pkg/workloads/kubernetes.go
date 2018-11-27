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

	k8sDockerLbls "k8s.io/kubernetes/pkg/kubelet/types"
)

// fetchK8sLabels returns the kubernetes labels from the given container labels
func fetchK8sLabels(containerID string, containerLbls map[string]string) (map[string]string, error) {
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
	return k8s.GetPodLabels(ns, podName)
}
