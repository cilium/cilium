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
)

const (
	// AnnotationName is an optional annotation to the NetworkPolicy
	// resource which specifies the name of the policy node to which all
	// rules should be applied to.
	AnnotationName = "io.cilium.name"
	// EnvNodeNameSpec is the environment label used by Kubernetes to
	// specify the node's name.
	EnvNodeNameSpec = "K8S_NODE_NAME"
	// LabelSource is the default label source for the labels imported from
	// kubernetes.
	LabelSource = "k8s"
	// DefaultPolicyParentPath is the default path to the policy node
	// received from kubernetes.
	DefaultPolicyParentPath = "k8s"
	// DefaultPolicyParentPathPrefix is the DefaultPolicyParentPath with the
	// NodePathDelimiter.
	DefaultPolicyParentPathPrefix = DefaultPolicyParentPath + NodePathDelimiter

	// NodePathDelimiter is the label's key path delimiter.
	NodePathDelimiter = "."

	// PolicyLabelName is the name of the policy label which refers to the
	// k8s policy name
	PolicyLabelName = "io.cilium.k8s-policy-name"
	// PodNamespaceLabel is the label used in kubernetes containers to
	// specify which namespace they belong to.
	PodNamespaceLabel = types.KubernetesPodNamespaceLabel
)
