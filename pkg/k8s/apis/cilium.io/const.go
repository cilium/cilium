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

package ciliumio

const (
	// PolicyLabelName is the name of the policy label which refers to the
	// k8s policy name.
	PolicyLabelName = "io.cilium.k8s.policy.name"

	// PolicyLabelUID is the uid of the policy label which refers to the
	// k8s policy UID.
	PolicyLabelUID = "io.cilium.k8s.policy.uid"

	// PolicyLabelNamespace is the policy's namespace set in k8s.
	PolicyLabelNamespace = "io.cilium.k8s.policy.namespace"

	// PolicyLabelDerivedFrom is the resource type which was used to
	// derived the policy rule
	PolicyLabelDerivedFrom = "io.cilium.k8s.policy.derived-from"

	// PolicyLabelServiceAccount is the name of the label associated with
	// an endpoint to represent the Kubernetes ServiceAccount name
	PolicyLabelServiceAccount = "io.cilium.k8s.policy.serviceaccount"

	// PolicyLabelCluster is the name of the cluster the endpoint is
	// running in
	PolicyLabelCluster = "io.cilium.k8s.policy.cluster"

	// PolicyLabelIstioSidecarProxy is the label key added to the identity of
	// any pod that has been injected by Istio with a Cilium-compatible sidecar
	// proxy. The value of this label is expected to be a boolean, i.e. "true"
	// or "false".
	PolicyLabelIstioSidecarProxy = "io.cilium.k8s.policy.istiosidecarproxy"

	// PodNamespaceMetaLabels is the label used to store the labels of the
	// kubernetes namespace's labels.
	PodNamespaceMetaLabels = "io.cilium.k8s.namespace.labels"
	// PodNamespaceLabel is the label used in kubernetes containers to
	// specify which namespace they belong to.
	PodNamespaceLabel = "io.kubernetes.pod.namespace"
	// PodNameLabel is the label used in kubernetes containers to
	// specify the POD name.
	PodNameLabel = "io.kubernetes.pod.name"
	// AppKubernetes is the label which is recommended by the official k8s
	// documentation ad the lablel for every resource object.
	AppKubernetes = "app.kubernetes.io"
	// CtrlPrefixPolicyStatus is the prefix used for the controllers set up
	// to sync the CNP with kube-apiserver.
	CtrlPrefixPolicyStatus = "sync-cnp-policy-status"

	// CiliumK8sAnnotationPrefix is the prefix key for the annotations used in kubernetes.
	CiliumK8sAnnotationPrefix = "cilium.io/"
	// CiliumIdentityAnnotationDeprecated is the previous annotation key used to map to an endpoint's security identity.
	CiliumIdentityAnnotationDeprecated = "cilium-identity"
)

const (
	// V1 represents version 1 of cilium API
	// Deprecated
	V1 = iota
	// V2 represents version 2 of cilium API
	V2
)
