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

package apis

import (
	"k8s.io/kubernetes/pkg/kubelet/types"
)

const (
	// PolicyLabelName is the name of the policy label which refers to the
	// k8s policy name.
	PolicyLabelName = "io.cilium.k8s.policy.name"
	// PolicyLabelNamespace is the policy's namespace set in k8s.
	PolicyLabelNamespace = "io.cilium.k8s.policy.namespace"
	// PodNamespaceMetaLabels is the label used to store the labels of the
	// kubernetes namespace's labels.
	PodNamespaceMetaLabels = "io.cilium.k8s.namespace.labels"
	// PodNamespaceLabel is the label used in kubernetes containers to
	// specify which namespace they belong to.
	PodNamespaceLabel = types.KubernetesPodNamespaceLabel
	// CtrlPrefixPolicyStatus is the prefix used for the controllers set up
	// to sync the CNP with kube-apiserver.
	CtrlPrefixPolicyStatus = "sync-cnp-policy-status"
)

const (
	// V1 represents version 1 of cilium API
	// Deprecated
	V1 = iota
	// V2 represents version 2 of cilium API
	V2
)
