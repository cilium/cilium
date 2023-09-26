// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
	// documentation add the label for every resource object.
	AppKubernetes = "app.kubernetes.io"

	// StatefulSetPodNameLabel is the label name which, in-tree, is used to
	// automatically label Pods that are owned by StatefulSets with their name,
	// so that one can attach a Service to a specific Pod in the StatefulSet.
	StatefulSetPodNameLabel = "statefulset.kubernetes.io/pod-name"

	// StatefulSetPodIndexLabel is the label name which, in-tree, is used to
	// automatically label Pods that are owned by StatefulSets with their
	// ordinal index.
	StatefulSetPodIndexLabel = "apps.kubernetes.io/pod-index"

	// CtrlPrefixPolicyStatus is the prefix used for the controllers set up
	// to sync the CNP with kube-apiserver.
	CtrlPrefixPolicyStatus = "sync-cnp-policy-status"

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
