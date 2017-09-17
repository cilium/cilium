/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cm

import (
	"k8s.io/api/core/v1"

	utilfeature "k8s.io/apiserver/pkg/util/feature"
	kubefeatures "k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpumanager"
)

type InternalContainerLifecycle interface {
	PreStartContainer(pod *v1.Pod, container *v1.Container, containerID string) error
	PreStopContainer(containerID string) error
	PostStopContainer(containerID string) error
}

// Implements InternalContainerLifecycle interface.
type internalContainerLifecycleImpl struct {
	cpuManager cpumanager.Manager
}

func (i *internalContainerLifecycleImpl) PreStartContainer(pod *v1.Pod, container *v1.Container, containerID string) error {
	if utilfeature.DefaultFeatureGate.Enabled(kubefeatures.CPUManager) {
		return i.cpuManager.AddContainer(pod, container, containerID)
	}
	return nil
}

func (i *internalContainerLifecycleImpl) PreStopContainer(containerID string) error {
	if utilfeature.DefaultFeatureGate.Enabled(kubefeatures.CPUManager) {
		return i.cpuManager.RemoveContainer(containerID)
	}
	return nil
}

func (i *internalContainerLifecycleImpl) PostStopContainer(containerID string) error {
	if utilfeature.DefaultFeatureGate.Enabled(kubefeatures.CPUManager) {
		return i.cpuManager.RemoveContainer(containerID)
	}
	return nil
}
