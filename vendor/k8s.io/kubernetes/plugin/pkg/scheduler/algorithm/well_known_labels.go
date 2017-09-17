/*
Copyright 2015 The Kubernetes Authors.

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

package algorithm

const (
	// When feature-gate for TaintBasedEvictions=true flag is enabled,
	// TaintNodeNotReady would be automatically added by node controller
	// when node is not ready, and removed when node becomes ready.
	TaintNodeNotReady = "node.alpha.kubernetes.io/notReady"

	// When feature-gate for TaintBasedEvictions=true flag is enabled,
	// TaintNodeUnreachable would be automatically added by node controller
	// when node becomes unreachable (corresponding to NodeReady status ConditionUnknown)
	// and removed when node becomes reachable (NodeReady status ConditionTrue).
	TaintNodeUnreachable = "node.alpha.kubernetes.io/unreachable"

	// When feature-gate for TaintBasedEvictions=true flag is enabled,
	// TaintNodeOutOfDisk would be automatically added by node controller
	// when node becomes out of disk, and removed when node has enough disk.
	TaintNodeOutOfDisk = "node.kubernetes.io/outOfDisk"

	// When feature-gate for TaintBasedEvictions=true flag is enabled,
	// TaintNodeMemoryPressure would be automatically added by node controller
	// when node has memory pressure, and removed when node has enough memory.
	TaintNodeMemoryPressure = "node.kubernetes.io/memoryPressure"

	// When feature-gate for TaintBasedEvictions=true flag is enabled,
	// TaintNodeDiskPressure would be automatically added by node controller
	// when node has disk pressure, and removed when node has enough disk.
	TaintNodeDiskPressure = "node.kubernetes.io/diskPressure"

	// When feature-gate for TaintBasedEvictions=true flag is enabled,
	// TaintNodeNetworkUnavailable would be automatically added by node controller
	// when node's network is unavailable, and removed when network becomes ready.
	TaintNodeNetworkUnavailable = "node.kubernetes.io/networkUnavailable"

	// When kubelet is started with the "external" cloud provider, then
	// it sets this taint on a node to mark it as unusable, until a controller
	// from the cloud-controller-manager intitializes this node, and then removes
	// the taint
	TaintExternalCloudProvider = "node.cloudprovider.kubernetes.io/uninitialized"
)
