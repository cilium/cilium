// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package defaults

import "time"

const (
	AgentContainerName      = "cilium-agent"
	AgentServiceAccountName = "cilium"
	AgentClusterRoleName    = "cilium"
	AgentDaemonSetName      = "cilium"
	AgentResourceQuota      = "cilium-resource-quota"
	AgentImage              = "quay.io/cilium/cilium"

	CASecretName     = "cilium-ca"
	CASecretKeyName  = "ca.key"
	CASecretCertName = "ca.crt"

	EncryptionSecretName = "cilium-ipsec-keys"

	OperatorServiceAccountName = "cilium-operator"
	OperatorClusterRoleName    = "cilium-operator"
	OperatorDeploymentName     = "cilium-operator"
	OperatorResourceQuota      = "cilium-operator-resource-quota"
	OperatorImage              = "quay.io/cilium/operator-generic"
	OperatorImageAWS           = "quay.io/cilium/operator-aws"
	OperatorImageAzure         = "quay.io/cilium/operator-azure"

	HubbleSocketPath       = "/var/run/cilium/hubble.sock"
	HubbleServerSecretName = "hubble-server-certs"

	RelayContainerName        = "hubble-relay"
	RelayDeploymentName       = "hubble-relay"
	RelayClusterRoleName      = "hubble-relay"
	RelayServiceAccountName   = "hubble-relay"
	RelayServiceName          = "hubble-relay"
	RelayConfigMapName        = "hubble-relay-config"
	RelayImage                = "quay.io/cilium/hubble-relay"
	RelayListenHost           = ""
	RelayPort                 = 4245
	RelayServicePlaintextPort = 80
	RelayServiceTLSPort       = 443
	RelayServerSecretName     = "hubble-relay-server-certs"
	RelayClientSecretName     = "hubble-relay-client-certs"

	HubbleUIServiceName        = "hubble-ui"
	HubbleUIClusterRoleName    = "hubble-ui"
	HubbleUIServiceAccountName = "hubble-ui"
	HubbleUIConfigMapName      = "hubble-ui-envoy"
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
	ConnectivityCheckJSONMockImage   = "quay.io/cilium/json-mock:v1.3.0@sha256:2729064827fa9dbfface8d3df424feb6c792a0ba07117b844349635c93c06d2b"

	ConfigMapName   = "cilium-config"
	Version         = "v1.11.0"
	HubbleUIVersion = "v0.8.5"

	TunnelType = "vxlan"

	StatusWaitDuration = 5 * time.Minute

	WaitRetryInterval   = 2 * time.Second
	WaitWarningInterval = 10 * time.Second

	FlowWaitTimeout   = 10 * time.Second
	FlowRetryInterval = 500 * time.Millisecond

	PolicyWaitTimeout = 15 * time.Second

	ConfigMapKeyMonitorAggregation      = "monitor-aggregation"
	ConfigMapValueMonitorAggregatonNone = "none"

	IngressClassName      = "cilium"
	IngressControllerName = "cilium.io/ingress-controller"
)

var (
	// OperatorLabels are the labels set on the Cilium operator by default.
	OperatorLabels = map[string]string{
		"io.cilium/app": "operator",
		"name":          "cilium-operator",
	}

	// RelayDeploymentLabels are the labels set on the Hubble Relay Deployment by default.
	RelayDeploymentLabels = map[string]string{
		"k8s-app": "hubble-relay",
	}

	// HubbleUIDeploymentLabels are the labels set on the Hubble UI Deployment by default.
	HubbleUIDeploymentLabels = map[string]string{
		"k8s-app": "hubble-ui",
	}

	// ClusterMeshDeploymentLabels are the labels set on the clustermesh API server by default.
	ClusterMeshDeploymentLabels = map[string]string{
		"k8s-app": "clustermesh-apiserver",
	}

	// CiliumPodSelector is the pod selector to be used for the Cilium agents.
	CiliumPodSelector = "k8s-app=cilium"
)
