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
		"Unknown ICMPv6 code",
		"Forbidden ICMPv6 message",
		"No egress gateway found",
	}

	ExpectedXFRMErrors = []string{
		"inbound_forward_header", // XfrmFwdHdrError
		"inbound_other",          // XfrmInError
		"inbound_state_invalid",  // XfrmInStateInvalid
	}

	LogCodeOwners  = false
	LogCheckLevels = []string{
		LogLevelError,
		LogLevelWarning,
	}

	ConnectivityCheckImagesTest = map[string]string{
		// renovate: datasource=docker
		"ConnectivityCheckAlpineCurlImage": "quay.io/cilium/alpine-curl:v1.10.0@sha256:913e8c9f3d960dde03882defa0edd3a919d529c2eb167caa7f54194528bde364",
		// renovate: datasource=docker
		"ConnectivityCheckJSONMockImage": "quay.io/cilium/json-mock:v1.4.0@sha256:500dc80291d4f402462e4bb7ecfc2b726f08c8136999e5e91cdd54f9e90eebeb",
		// renovate: datasource=docker
		"ConnectivityDNSTestServerImage": "registry.k8s.io/coredns/coredns:v1.14.4@sha256:3e98f280fd601b37411c5fb7075fd9f337833c480f1644970b727ae0af067782",
		// renovate: datasource=docker
		"ConnectivityTestConnDisruptImage": "quay.io/cilium/test-connection-disruption:v0.0.17@sha256:62374cfd0e87e6541244331ccf477a21c527c3eefa9d841b97af79996939be0c",
		// renovate: datasource=docker
		"ConnectivityTestFRRImage": "quay.io/frrouting/frr:10.6.1@sha256:813497af103e972600f6161012b3bf2a2a1c5ea10d09cd1eacd74f1dc510a57b",
		// renovate: datasource=docker
		"ConnectivityTestSocatImage": "docker.io/alpine/socat:1.8.1.3@sha256:188fe0a22182f81c16def9d1137930121eaa3023f427164e32c0d2f118f79dd6",
	}

	ConnectivityCheckOptionalImagesTest = map[string]string{
		// renovate: datasource=docker
		"ConnectivityTestEchoImage": "gcr.io/k8s-staging-gateway-api/echo-advanced:v20251204-v1.4.1",
	}

	ConnectivityCheckImagesPerf = map[string]string{
		// renovate: datasource=docker
		"ConnectivityPerformanceImage": "quay.io/cilium/network-perf:3.21-1782913202-88c270c@sha256:c115a00b80bbf4ff49857dd545f0c40025f226d79051b2c8fdab3e8b938c7f92",
	}

	// The following variables are set at compile time via LDFLAGS.

	// CLIVersion is the software version of the Cilium CLI.
	CLIVersion string
)
