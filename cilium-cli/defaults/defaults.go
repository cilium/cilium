// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package defaults

import "time"

const (
	AgentContainerName      = "cilium-agent"
	AgentServiceAccountName = "cilium"
	AgentClusterRoleName    = "cilium"
	AgentSecretsRoleName    = "cilium-secrets"
	AgentDaemonSetName      = "cilium"
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
	ClusterMeshServiceAccountName         = "clustermesh-apiserver"
	ClusterMeshClusterRoleName            = "clustermesh-apiserver"
	ClusterMeshApiserverImage             = "quay.io/cilium/clustermesh-apiserver"
	ClusterMeshServiceName                = "clustermesh-apiserver"
	ClusterMeshSecretName                 = "cilium-clustermesh" // Secret which contains the clustermesh configuration
	ClusterMeshServerSecretName           = "clustermesh-apiserver-server-certs"
	ClusterMeshAdminSecretName            = "clustermesh-apiserver-admin-certs"
	ClusterMeshClientSecretName           = "clustermesh-apiserver-client-certs"
	ClusterMeshExternalWorkloadSecretName = "clustermesh-apiserver-external-workload-certs"

	ConnectivityCheckNamespace = "cilium-test"

	ConnectivityCheckAlpineCurlImage = "quay.io/cilium/alpine-curl:v1.4.0@sha256:2550c747831ff575f2147149b088ea981c06f9b6bcd188756d1b82cc10997956"
	ConnectivityPerformanceImage     = "quay.io/cilium/network-perf:bf58fb8bc57c4933dfa6e2a9581d3925c0a0571e@sha256:9bef508b2dcaeb3e288a496b8d3f065e8636a4937ba3aebcb1732afffaccea34"
	ConnectivityCheckJSONMockImage   = "quay.io/cilium/json-mock:v1.3.0@sha256:2729064827fa9dbfface8d3df424feb6c792a0ba07117b844349635c93c06d2b"
	ConnectivityDNSTestServerImage   = "docker.io/coredns/coredns:1.9.3@sha256:8e352a029d304ca7431c6507b56800636c321cb52289686a581ab70aaa8a2e2a"

	ConfigMapName = "cilium-config"
	Version       = "v1.11.6"

	StatusWaitDuration = 5 * time.Minute

	WaitRetryInterval   = 2 * time.Second
	WaitWarningInterval = 10 * time.Second

	FlowWaitTimeout   = 10 * time.Second
	FlowRetryInterval = 500 * time.Millisecond

	PolicyWaitTimeout = 15 * time.Second

	ConfigMapKeyMonitorAggregation      = "monitor-aggregation"
	ConfigMapValueMonitorAggregatonNone = "none"

	IngressClassName        = "cilium"
	IngressControllerName   = "cilium.io/ingress-controller"
	IngressSecretsNamespace = "cilium-secrets"

	HelmValuesSecretName          = "cilium-cli-helm-values"
	HelmValuesSecretKeyName       = "io.cilium.cilium-cli"
	HelmChartVersionSecretKeyName = "io.cilium.chart-version"
)

var (
	// ClusterMeshDeploymentLabels are the labels set on the clustermesh API server by default.
	ClusterMeshDeploymentLabels = map[string]string{
		"k8s-app": "clustermesh-apiserver",
	}

	// CiliumPodSelector is the pod selector to be used for the Cilium agents.
	CiliumPodSelector = "k8s-app=cilium"
)
