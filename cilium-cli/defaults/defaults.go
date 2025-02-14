// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package defaults

import (
	"crypto/sha256"
	"time"
)

const (
	CiliumPodSelector = "app.kubernetes.io/part-of=cilium"

	AgentContainerName   = "cilium-agent"
	AgentClusterRoleName = "cilium"
	AgentDaemonSetName   = "cilium"
	AgentPodSelector     = "k8s-app=cilium"

	EnvoyDaemonSetName = "cilium-envoy"
	EnvoyConfigMapName = "cilium-envoy-config"

	CASecretName     = "cilium-ca"
	CASecretCertName = "ca.crt"

	EncryptionSecretName = "cilium-ipsec-keys"

	OperatorPodSelector     = "io.cilium/app=operator"
	OperatorContainerName   = "cilium-operator"
	OperatorMetricsPortName = "prometheus"
	OperatorDeploymentName  = "cilium-operator"

	RelayContainerName  = "hubble-relay"
	RelayDeploymentName = "hubble-relay"
	RelayConfigMapName  = "hubble-relay-config"
	RelayPodSelector    = "app.kubernetes.io/name=hubble-relay"

	HubbleUIDeploymentName = "hubble-ui"

	HubbleGenerateCertsCronJobName = "hubble-generate-certs"

	ClusterMeshDeploymentName              = "clustermesh-apiserver"
	ClusterMeshBinaryName                  = "/usr/bin/clustermesh-apiserver"
	ClusterMeshContainerName               = "apiserver"
	ClusterMeshPodSelector                 = "k8s-app=clustermesh-apiserver"
	ClusterMeshMetricsPortName             = "apiserv-metrics"
	ClusterMeshKVStoreMeshContainerName    = "kvstoremesh"
	ClusterMeshKVStoreMeshMetricsPortName  = "kvmesh-metrics"
	ClusterMeshEtcdContainerName           = "etcd"
	ClusterMeshEtcdMetricsPortName         = "etcd-metrics"
	ClusterMeshServiceName                 = "clustermesh-apiserver"
	ClusterMeshSecretName                  = "cilium-clustermesh" // Secret which contains the clustermesh configuration
	ClusterMeshKVStoreMeshSecretName       = "cilium-kvstoremesh" // Secret which contains the kvstoremesh configuration
	ClusterMeshServerSecretName            = "clustermesh-apiserver-server-cert"
	ClusterMeshAdminSecretName             = "clustermesh-apiserver-admin-cert"
	ClusterMeshClientSecretName            = "clustermesh-apiserver-client-cert"
	ClusterMeshRemoteSecretName            = "clustermesh-apiserver-remote-cert"
	ClusterMeshConnectionModeBidirectional = "bidirectional"
	ClusterMeshConnectionModeMesh          = "mesh"
	ClusterMeshConnectionModeUnicast       = "unicast"

	SPIREServerStatefulSetName = "spire-server"
	SPIREServerConfigMapName   = "spire-server"
	SPIREAgentDaemonSetName    = "spire-agent"
	SPIREAgentConfigMapName    = "spire-agent"

	ConnectivityCheckNamespace = "cilium-test"

	// renovate: datasource=docker
	ConnectivityCheckAlpineCurlImage = "quay.io/cilium/alpine-curl:v1.10.0@sha256:913e8c9f3d960dde03882defa0edd3a919d529c2eb167caa7f54194528bde364"
	// renovate: datasource=docker
	ConnectivityPerformanceImage = "quay.io/cilium/network-perf:a816f935930cb2b40ba43230643da4d5751a5711@sha256:679d3a370c696f63884da4557a4466f3b5569b4719bb4f86e8aac02fbe390eea"
	// renovate: datasource=docker
	ConnectivityCheckJSONMockImage = "quay.io/cilium/json-mock:v1.3.8@sha256:5aad04835eda9025fe4561ad31be77fd55309af8158ca8663a72f6abb78c2603"
	// renovate: datasource=docker
	ConnectivityDNSTestServerImage = "docker.io/coredns/coredns:1.12.0@sha256:40384aa1f5ea6bfdc77997d243aec73da05f27aed0c5e9d65bfa98933c519d97"
	// renovate: datasource=docker
	ConnectivityTestConnDisruptImage = "quay.io/cilium/test-connection-disruption:v0.0.14@sha256:c3fd56e326ae16f6cb63dbb2e26b4e47ec07a123040623e11399a7fe1196baa0"
	// renovate: datasource=docker
	ConnectivityTestFRRImage = "quay.io/frrouting/frr:10.2.1@sha256:c8543d3e0a1348cc0f2b19154fd8b0300e237773dbec65d9d6d6570c1d088deb"
	// renovate: datasource=docker
	ConnectivityTestSocatImage = "docker.io/alpine/socat:1.8.0.1@sha256:e899028c84c1a1e65bb14821b0802a683a2cffbff96c9ac02ff1d9cbb03f64e6"

	ConfigMapName = "cilium-config"

	StatusWaitDuration = 5 * time.Minute

	WaitRetryInterval   = 2 * time.Second
	WaitWarningInterval = 10 * time.Second

	FlowWaitTimeout   = 10 * time.Second
	FlowRetryInterval = 500 * time.Millisecond

	PolicyWaitTimeout = 30 * time.Second

	ConnectRetry      = 3
	ConnectRetryDelay = 3 * time.Second

	CurlParallel = 0

	ConnectTimeout = 2 * time.Second
	RequestTimeout = 10 * time.Second

	UninstallTimeout = 5 * time.Minute

	IngressClassName = "cilium"

	HelmValuesSecretName = "cilium-cli-helm-values"

	CiliumNoScheduleLabel = "cilium.io/no-schedule"

	// ClustermeshMaxConnectedClusters is the default number of the maximum
	// number of clusters that should be allowed to connect to the Clustermesh.
	ClustermeshMaxConnectedClusters = 255

	// Default timeout for Connectivity Test Suite (disabled by default)
	ConnectivityTestSuiteTimeout = 0 * time.Minute

	LogLevelError   = "error"
	LogLevelWarning = "warning"
)

var (
	// HelmRepository specifies Helm repository to download Cilium charts from.
	HelmRepoIDLen    = 4
	HelmRepository   = "https://helm.cilium.io"
	HelmRepositoryID = sha256.Sum256([]byte(HelmRepository))
	HelmMaxHistory   = 10

	// CiliumScheduleAffinity is the node affinity to prevent Cilium from being schedule on
	// nodes labeled with CiliumNoScheduleLabel.
	CiliumScheduleAffinity = []string{
		"affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key=" + CiliumNoScheduleLabel,
		"affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].operator=NotIn",
		"affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].values[0]=true",
	}

	// CiliumOperatorScheduleAffinity is the node affinity to prevent Cilium from being schedule on
	// nodes labeled with CiliumNoScheduleLabel.
	CiliumOperatorScheduleAffinity = []string{
		"operator.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key=" + CiliumNoScheduleLabel,
		"operator.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].operator=NotIn",
		"operator.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].values[0]=true",
	}

	// SpireAgentScheduleAffinity is the node affinity to prevent the SPIRE agent from being scheduled on
	// nodes labeled with CiliumNoScheduleLabel.
	SpireAgentScheduleAffinity = []string{
		"authentication.mutual.spire.install.agent.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key=" + CiliumNoScheduleLabel,
		"authentication.mutual.spire.install.agent.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].operator=NotIn",
		"authentication.mutual.spire.install.agent.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].values[0]=true",
	}

	ExpectedDropReasons = []string{
		"Policy denied",
		"Policy denied by denylist",
		"Unsupported L2 protocol",
		"Unsupported L3 protocol",
		"Stale or unroutable IP",
		"Authentication required",
		"Service backend not found",
		"Unsupported protocol for NAT masquerade",
		"Invalid source ip",
		"Unknown L3 target address",
		"Host datapath not ready",
		"Unknown ICMPv4 code",
		"Forbidden ICMPv6 message",
		"No egress gateway found",
	}

	ExpectedXFRMErrors = []string{
		"inbound_forward_header", // XfrmFwdHdrError
		"inbound_other",          // XfrmInError
		"inbound_state_invalid",  // XfrmInStateInvalid
	}

	LogCheckLevels = []string{
		LogLevelError,
		LogLevelWarning,
	}

	// The following variables are set at compile time via LDFLAGS.

	// CLIVersion is the software version of the Cilium CLI.
	CLIVersion string
)
