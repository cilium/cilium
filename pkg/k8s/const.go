// Copyright 2016-2017 Authors of Cilium
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

package k8s

import (
	"k8s.io/kubernetes/pkg/kubelet/types"
	"time"
)

const (
	// AnnotationName is an optional annotation to the NetworkPolicy
	// resource which specifies the name of the policy node to which all
	// rules should be applied to.
	AnnotationName = "io.cilium.name"

	// Annotationv4CIDRName is the annotation name used to store the IPv4
	// pod CIDR in the node's annotations.
	Annotationv4CIDRName = "io.cilium.network.ipv4-pod-cidr"
	// Annotationv6CIDRName is the annotation name used to store the IPv6
	// pod CIDR in the node's annotations.
	Annotationv6CIDRName = "io.cilium.network.ipv6-pod-cidr"

	// EnvNodeNameSpec is the environment label used by Kubernetes to
	// specify the node's name.
	EnvNodeNameSpec = "K8S_NODE_NAME"

	// PolicyLabelName is the name of the policy label which refers to the
	// k8s policy name
	PolicyLabelName = "io.cilium.k8s-policy-name"
	// PodNamespaceLabel is the label used in kubernetes containers to
	// specify which namespace they belong to.
	PodNamespaceLabel = types.KubernetesPodNamespaceLabel
	// PodNamespaceMetaLabels is the label used to store the labels of the
	// kubernetes namespace's labels.
	PodNamespaceMetaLabels = "ns-labels"

	// BackOffLoopTimeout is the default duration when trying to reach the
	// kube-apiserver.
	BackOffLoopTimeout = 2 * time.Minute

	// maxUpdateRetries is the maximum number of update retries when
	// updating k8s resources
	maxUpdateRetries = 30
)
