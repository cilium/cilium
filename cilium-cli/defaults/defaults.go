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
		"ConnectivityCheckJSONMockImage": "quay.io/cilium/json-mock:v1.3.9@sha256:c98b26177a5a60020e5aa404896d55f0ab573d506f42acfb4aa4f5705a5c6f56",
		// renovate: datasource=docker
		"ConnectivityDNSTestServerImage": "registry.k8s.io/coredns/coredns:v1.12.4@sha256:986f04c2e15e147d00bdd51e8c51bcef3644b13ff806be7d2ff1b261d6dfbae1",
		// renovate: datasource=docker
		"ConnectivityTestConnDisruptImage": "quay.io/cilium/test-connection-disruption:v0.0.17@sha256:62374cfd0e87e6541244331ccf477a21c527c3eefa9d841b97af79996939be0c",
		// renovate: datasource=docker
		"ConnectivityTestFRRImage": "quay.io/frrouting/frr:10.5.1@sha256:848482643a8d6f56452b659ea68f6138472bb57414a4f295a7c4107a0416269c",
		// renovate: datasource=docker
		"ConnectivityTestSocatImage": "docker.io/alpine/socat:1.8.0.3@sha256:113d76e6fcb1e8cb7fc0f513953667020ad4733b86a8a3f36ee1628fbf7be2b8",
	}

	ConnectivityCheckOptionalImagesTest = map[string]string{
		// renovate: datasource=docker
		"ConnectivityTestEchoImage": "gcr.io/k8s-staging-gateway-api/echo-advanced:v20240412-v1.0.0-394-g40c666fd",
	}

	ConnectivityCheckImagesPerf = map[string]string{
		// renovate: datasource=docker
		"ConnectivityPerformanceImage": "quay.io/cilium/network-perf:3.20-1767778631-6ec32c1@sha256:7e119abe9dfe058d1c89aa72bf1528f973646bedfb32a00d9ba36d6f4ed75d43",
	}

	// The following variables are set at compile time via LDFLAGS.

	// CLIVersion is the software version of the Cilium CLI.
	CLIVersion string
)
