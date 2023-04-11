// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package defaults

import "time"

const (
	AgentContainerName      = "cilium-agent"
	AgentServiceAccountName = "cilium"
	AgentClusterRoleName    = "cilium"
	AgentSecretsRoleName    = "cilium-secrets"
	AgentConfigRoleName     = "cilium-config-agent"
	AgentDaemonSetName      = "cilium"
	AgentPodSelector        = "k8s-app=cilium"
	AgentResourceQuota      = "cilium-resource-quota"
	AgentImage              = "quay.io/cilium/cilium"

	CASecretName     = "cilium-ca"
	CASecretKeyName  = "ca.key"
	CASecretCertName = "ca.crt"

	EncryptionSecretName = "cilium-ipsec-keys"
	AKSSecretName        = "cilium-azure"

	NodeInitDaemonSetName = "cilium-node-init"

	OperatorServiceAccountName = "cilium-operator"
	OperatorClusterRoleName    = "cilium-operator"
	OperatorSecretsRoleName    = "cilium-operator-secrets"
	OperatorContainerName      = "cilium-operator"
	OperatorDeploymentName     = "cilium-operator"
	OperatorResourceQuota      = "cilium-operator-resource-quota"
	OperatorImage              = "quay.io/cilium/operator-generic"
	OperatorImageAWS           = "quay.io/cilium/operator-aws"
	OperatorImageAzure         = "quay.io/cilium/operator-azure"

	HubbleServerSecretName = "hubble-server-certs"

	RelayContainerName       = "hubble-relay"
	RelayDeploymentName      = "hubble-relay"
	RelayClusterRoleName     = "hubble-relay"
	RelayServiceAccountName  = "hubble-relay"
	RelayConfigMapName       = "hubble-relay-config"
	RelayImage               = "quay.io/cilium/hubble-relay"
	RelayServerSecretName    = "hubble-relay-server-certs"
	RelayClientSecretName    = "hubble-relay-client-certs"
	HubbleUIClientSecretName = "hubble-ui-client-certs"

	HubbleUIClusterRoleName    = "hubble-ui"
	HubbleUIServiceAccountName = "hubble-ui"
	HubbleUIDeploymentName     = "hubble-ui"
	HubbleUIImage              = "quay.io/cilium/hubble-ui"
	HubbleUIBackendImage       = "quay.io/cilium/hubble-ui-backend"

	ClusterMeshDeploymentName             = "clustermesh-apiserver"
	ClusterMeshContainerName              = "apiserver"
	ClusterMeshServiceAccountName         = "clustermesh-apiserver"
	ClusterMeshClusterRoleName            = "clustermesh-apiserver"
	ClusterMeshApiserverImage             = "quay.io/cilium/clustermesh-apiserver"
	ClusterMeshServiceName                = "clustermesh-apiserver"
	ClusterMeshSecretName                 = "cilium-clustermesh" // Secret which contains the clustermesh configuration
	ClusterMeshServerSecretName           = "clustermesh-apiserver-server-cert"
	ClusterMeshAdminSecretName            = "clustermesh-apiserver-admin-cert"
	ClusterMeshClientSecretName           = "clustermesh-apiserver-client-cert"
	ClusterMeshExternalWorkloadSecretName = "clustermesh-apiserver-external-workload-cert"

	ConnectivityCheckNamespace = "cilium-test"

	ConnectivityCheckAlpineCurlImage = "quay.io/cilium/alpine-curl:v1.6.0@sha256:408430f548a8390089b9b83020148b0ef80b0be1beb41a98a8bfe036709c196e"
	ConnectivityPerformanceImage     = "quay.io/cilium/network-perf:a816f935930cb2b40ba43230643da4d5751a5711@sha256:679d3a370c696f63884da4557a4466f3b5569b4719bb4f86e8aac02fbe390eea"
	ConnectivityCheckJSONMockImage   = "quay.io/cilium/json-mock:v1.3.4@sha256:d5fbc5d7762530b53af27b0ba247e61a2fa5da42c8b5a58956933fe6a6ce15b8"
	ConnectivityDNSTestServerImage   = "docker.io/coredns/coredns:1.10.0@sha256:017727efcfeb7d053af68e51436ce8e65edbc6ca573720afb4f79c8594036955"

	ConfigMapName = "cilium-config"
	Version       = "v1.13.1"

	StatusWaitDuration = 5 * time.Minute

	WaitRetryInterval   = 2 * time.Second
	WaitWarningInterval = 10 * time.Second

	FlowWaitTimeout   = 10 * time.Second
	FlowRetryInterval = 500 * time.Millisecond

	PolicyWaitTimeout = 15 * time.Second

	ConnectTimeout = 2 * time.Second
	RequestTimeout = 10 * time.Second

	IngressClassName        = "cilium"
	IngressService          = "cilium-ingress"
	IngressControllerName   = "cilium.io/ingress-controller"
	IngressSecretsNamespace = "cilium-secrets"

	// HelmReleaseName is the default Helm release name for Cilium.
	HelmReleaseName               = "cilium"
	HelmValuesSecretName          = "cilium-cli-helm-values"
	HelmValuesSecretKeyName       = "io.cilium.cilium-cli"
	HelmChartVersionSecretKeyName = "io.cilium.chart-version"

	CiliumNoScheduleLabel = "cilium.io/no-schedule"
)

var (
	// ClusterMeshDeploymentLabels are the labels set on the clustermesh API server by default.
	ClusterMeshDeploymentLabels = map[string]string{
		"k8s-app": "clustermesh-apiserver",
	}

	// HubbleKeys are all hubble values from `cilium-config` configmap:
	// https://github.com/cilium/cilium/blob/d9a04be9d714e5f5544cbca7ef8db7a151bfce96/install/kubernetes/cilium/templates/cilium-configmap.yaml#L709-L750
	// this list is used to cherry-pick only hubble related values for configmap patch
	// when running in unknown install state (i.e. when `cilium-cli-helm-values` doesn't exist)
	HubbleKeys = []string{
		"enable-hubble",
		"hubble-disable-tls",
		"hubble-event-buffer-capacity",
		"hubble-event-queue-size",
		"hubble-flow-buffer-size",
		"hubble-listen-address",
		"hubble-metrics",
		"hubble-metrics-server",
		"hubble-socket-path",
		"hubble-tls-cert-file",
		"hubble-tls-client-ca-files",
		"hubble-tls-key-file",
	}

	// CiliumScheduleAffinity is the node affinity to prevent Cilium from being schedule on
	// nodes labeled with CiliumNoScheduleLabel.
	CiliumScheduleAffinity = []string{
		"affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key=" + CiliumNoScheduleLabel,
		"affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].operator=NotIn",
		"affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].values[0]=true",
	}
)
