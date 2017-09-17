/*
Copyright 2016 The Kubernetes Authors.

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

package kubelet

import (
	"fmt"

	"github.com/golang/glog"

	"k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/kubernetes/pkg/api/v1/resource"
)

// defaultPodLimitsForDownwardAPI copies the input pod, and optional container,
// and applies default resource limits. it returns a copy of the input pod,
// and a copy of the input container (if specified) with default limits
// applied. if a container has no limit specified, it will default the limit to
// the node allocatable.
// TODO: if/when we have pod level resources, we need to update this function
// to use those limits instead of node allocatable.
func (kl *Kubelet) defaultPodLimitsForDownwardAPI(pod *v1.Pod, container *v1.Container) (*v1.Pod, *v1.Container, error) {
	if pod == nil {
		return nil, nil, fmt.Errorf("invalid input, pod cannot be nil")
	}

	node, err := kl.getNodeAnyWay()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find node object, expected a node")
	}
	allocatable := node.Status.Allocatable
	glog.Infof("allocatable: %v", allocatable)
	podCopy, err := scheme.Scheme.Copy(pod)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to perform a deep copy of pod object: %v", err)
	}
	outputPod, ok := podCopy.(*v1.Pod)
	if !ok {
		return nil, nil, fmt.Errorf("unexpected type returned from deep copy of pod object")
	}
	for idx := range outputPod.Spec.Containers {
		resource.MergeContainerResourceLimits(&outputPod.Spec.Containers[idx], allocatable)
	}

	var outputContainer *v1.Container
	if container != nil {
		containerCopy, err := scheme.Scheme.DeepCopy(container)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to perform a deep copy of container object: %v", err)
		}
		outputContainer, ok = containerCopy.(*v1.Container)
		if !ok {
			return nil, nil, fmt.Errorf("unexpected type returned from deep copy of container object")
		}
		resource.MergeContainerResourceLimits(outputContainer, allocatable)
	}
	return outputPod, outputContainer, nil
}
