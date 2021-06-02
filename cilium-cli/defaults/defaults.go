// Copyright 2020-2021 Authors of Cilium
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

package defaults

import "time"

const (
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

	ConnectivityCheckAlpineCurlImage = "quay.io/cilium/alpine-curl:v1.3.0@sha256:1d928912e5d9dc9994b038b5df7434790c4bb9bd64f60570d78c1dee13befc76"
	ConnectivityCheckJSONMockImage   = "quay.io/cilium/json-mock:v1.3.0@sha256:2729064827fa9dbfface8d3df424feb6c792a0ba07117b844349635c93c06d2b"

	ConfigMapName = "cilium-config"
	Version       = "v1.9.8"

	TunnelType = "vxlan"

	WaitRetryInterval   = 2 * time.Second
	WaitWarningInterval = 10 * time.Second

	FlowWaitTimeout   = 10 * time.Second
	FlowRetryInterval = 500 * time.Millisecond

	PolicyWaitTimeout = 15 * time.Second

	ConfigMapKeyMonitorAggregation      = "monitor-aggregation"
	ConfigMapValueMonitorAggregatonNone = "none"
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
