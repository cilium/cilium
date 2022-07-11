// Copyright 2016-2021 Authors of Cilium
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
	// LabelPrefix is the prefix for all Cilium owned labels.
	LabelPrefix = "io.cilium.k8s"

	// PolicyLabelName is the name of the policy label which refers to the
	// k8s policy name.
	PolicyLabelName = LabelPrefix + ".policy.name"

	// PolicyLabelUID is the uid of the policy label which refers to the
	// k8s policy UID.
	PolicyLabelUID = LabelPrefix + ".policy.uid"

	// PolicyLabelNamespace is the policy's namespace set in k8s.
	PolicyLabelNamespace = LabelPrefix + ".policy.namespace"

	// PolicyLabelDerivedFrom is the resource type which was used to
	// derived the policy rule
	PolicyLabelDerivedFrom = LabelPrefix + ".policy.derived-from"

	// PolicyLabelServiceAccount is the name of the label associated with
	// an endpoint to represent the Kubernetes ServiceAccount name
	PolicyLabelServiceAccount = LabelPrefix + ".policy.serviceaccount"

	// PolicyLabelCluster is the name of the cluster the endpoint is
	// running in
	PolicyLabelCluster = LabelPrefix + ".policy.cluster"

	// PolicyLabelIstioSidecarProxy is the label key added to the identity of
	// any pod that has been injected by Istio with a Cilium-compatible sidecar
	// proxy. The value of this label is expected to be a boolean, i.e. "true"
	// or "false".
	PolicyLabelIstioSidecarProxy = LabelPrefix + ".policy.istiosidecarproxy"

	// PodNamespaceMetaLabels is the label used to store the labels of the
	// kubernetes namespace's labels.
	PodNamespaceMetaLabels = LabelPrefix + ".namespace.labels"

	// PodNamespaceMetaNameLabel is the label that Kubernetes automatically adds
	// to namespaces.
	PodNamespaceMetaNameLabel = PodNamespaceMetaLabels + "." + LabelMetadataName

	// LabelMetadataName is the label name which, in-tree, is used to
	// automatically label namespaces, so they can be selected easily by tools
	// which require definitive labels.
	LabelMetadataName = "kubernetes.io/metadata.name"

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

	// AgentNotReadyNodeTaint is a node taint which prevents pods from being
	// scheduled. Once cilium is setup it is removed from the node. Mostly
	// used in cloud providers to prevent existing CNI plugins from managing
	// pods.
	AgentNotReadyNodeTaint = "node." + CiliumK8sAnnotationPrefix + "agent-not-ready"
)

const (
	// V1 represents version 1 of cilium API
	// Deprecated
	V1 = iota
	// V2 represents version 2 of cilium API
	V2
)
