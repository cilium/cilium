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

package cpumanager

import (
	"github.com/golang/glog"
	"k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpumanager/state"
	"k8s.io/kubernetes/pkg/kubelet/status"
)

type fakeManager struct {
	state state.State
}

func (m *fakeManager) Start(activePods ActivePodsFunc, podStatusProvider status.PodStatusProvider, containerRuntime runtimeService) {
	glog.Info("[fake cpumanager] Start()")
}

func (m *fakeManager) Policy() Policy {
	glog.Info("[fake cpumanager] Policy()")
	return NewNonePolicy()
}

func (m *fakeManager) AddContainer(pod *v1.Pod, container *v1.Container, containerID string) error {
	glog.Infof("[fake cpumanager] AddContainer (pod: %s, container: %s, container id: %s)", pod.Name, container.Name, containerID)
	return nil
}

func (m *fakeManager) RemoveContainer(containerID string) error {
	glog.Infof("[fake cpumanager] RemoveContainer (container id: %s)", containerID)
	return nil
}

func (m *fakeManager) State() state.Reader {
	return m.state
}

// NewFakeManager creates empty/fake cpu manager
func NewFakeManager() Manager {
	return &fakeManager{
		state: state.NewMemoryState(),
	}
}
