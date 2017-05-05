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
	"strings"

	"k8s.io/kubernetes/pkg/kubelet/types"
)

const (
	// AnnotationIsolationNS is the annotation key used in the annotation
	// map for the network isolation on the respective namespace.
	AnnotationIsolationNS = "net.beta.kubernetes.io/network-policy"
	// AnnotationName is an optional annotation to the NetworkPolicy
	// resource which specifies the name of the policy node to which all
	// rules should be applied to.
	AnnotationName = "io.cilium.name"
	// AnnotationParentPath is an optional annotation to the NetworkPolicy
	// resource which specifies the path to the parent policy node to which
	// all must be merged into.
	AnnotationParentPath = "io.cilium.parent"
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
	// PodNamespaceLabel is the label used in kubernetes containers to
	// specify which namespace they belong to.
	PodNamespaceLabel = types.KubernetesPodNamespaceLabel
	// PodNamespaceLabelPrefix is the PodNamespaceLabel prefixed with
	// DefaultPolicyParentPathPrefix.
	PodNamespaceLabelPrefix = DefaultPolicyParentPathPrefix + PodNamespaceLabel
	// PodNamespaceMetaLabels is the label used to store the labels of the
	// kubernetes namespace's labels. This was carefully chosen, e.g. do not
	// change this to "io.kubernetes.pod.namespace.ns-labels" as the user
	// can pick a kubernetes namespace called "ns-labels", causing conflicts
	// between the namespaces' labels and the namespace's name.
	PodNamespaceMetaLabels = "io.cilium.k8s.ns-labels"

	// FIXME this is a duplicate from policy/defaults.go. Suggestion is to
	// moved to the policy/api

	// RootNodeName is the root node name for the policy tree
	RootNodeName = "root"
	// NodePathDelimiter is the label's key path del
	NodePathDelimiter = "."
	// RootPrefix is the prefix used in the label's absPath for the root
	// node.
	RootPrefix = RootNodeName + NodePathDelimiter
)

var (
	// LabelOwner should be the LabelOwner for all labels with the k8s
	// source.
	LabelOwner = &labelOwner{}
)

type labelOwner struct{}

// ResolveName resolves the given key to the proper full name for a k8s label.
func (k8s *labelOwner) ResolveName(key string) string {
	if strings.HasPrefix(key, RootPrefix) {
		return key
	}
	if strings.HasPrefix(key, DefaultPolicyParentPathPrefix) {
		return RootPrefix + key
	}
	return RootPrefix + DefaultPolicyParentPathPrefix + key
}
