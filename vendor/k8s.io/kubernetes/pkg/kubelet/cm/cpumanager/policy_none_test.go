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
	"testing"

	"k8s.io/kubernetes/pkg/kubelet/cm/cpuset"
)

func TestNonePolicyName(t *testing.T) {
	policy := &nonePolicy{}

	policyName := policy.Name()
	if policyName != "none" {
		t.Errorf("NonePolicy Name() error. expected: none, returned: %v",
			policyName)
	}
}

func TestNonePolicyAdd(t *testing.T) {
	policy := &nonePolicy{}

	st := &mockState{
		assignments:   map[string]cpuset.CPUSet{},
		defaultCPUSet: cpuset.NewCPUSet(1, 2, 3, 4, 5, 6, 7),
	}

	testPod := makePod("1000m", "1000m")

	container := &testPod.Spec.Containers[0]
	err := policy.AddContainer(st, testPod, container, "fakeID")
	if err != nil {
		t.Errorf("NonePolicy AddContainer() error. expected no error but got: %v", err)
	}
}

func TestNonePolicyRemove(t *testing.T) {
	policy := &nonePolicy{}

	st := &mockState{
		assignments:   map[string]cpuset.CPUSet{},
		defaultCPUSet: cpuset.NewCPUSet(1, 2, 3, 4, 5, 6, 7),
	}

	err := policy.RemoveContainer(st, "fakeID")
	if err != nil {
		t.Errorf("NonePolicy RemoveContainer() error. expected no error but got %v", err)
	}
}
