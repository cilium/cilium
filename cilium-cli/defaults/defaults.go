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

	HubbleSocketPath           = "/var/run/cilium/hubble.sock"
	HubbleServerSecretName     = "hubble-server-certs"
	HubbleServerSecretCertName = "tls.crt"
	HubbleServerSecretKeyName  = "tls.key"

	RelayDeploymentName       = "hubble-relay"
	RelayClusterRoleName      = "hubble-relay"
	RelayServiceAccountName   = "hubble-relay"
	RelayServiceName          = "hubble-relay"
	RelayConfigMapName        = "hubble-relay-config"
	RelayImage                = "quay.io/cilium/hubble-relay"
	RelayListenHost           = ""
	RelayPort                 = 4245
	RelayServerSecretName     = "hubble-relay-server-certs"
	RelayServerSecretCertName = "tls.crt"
	RelayServerSecretKeyName  = "tls.key"
	RelayClientSecretName     = "hubble-relay-client-certs"
	RelayClientSecretCertName = "tls.crt"
	RelayClientSecretKeyName  = "tls.key"

	ClusterMeshDeploymentName       = "clustermesh-apiserver"
	ClusterMeshServiceAccountName   = "clustermesh-apiserver"
	ClusterMeshClusterRoleName      = "clustermesh-apiserver"
	ClusterMeshApiserverImage       = "quay.io/cilium/clustermesh-apiserver:" + Version
	ClusterMeshServiceName          = "clustermesh-apiserver"
	ClusterMeshSecretName           = "cilium-clustermesh" // Secret which contains the clustermesh configuration
	ClusterMeshServerSecretName     = "clustermesh-apiserver-server-certs"
	ClusterMeshServerSecretCertName = "tls.crt"
	ClusterMeshServerSecretKeyName  = "tls.key"
	ClusterMeshAdminSecretName      = "clustermesh-apiserver-admin-certs"
	ClusterMeshAdminSecretCertName  = "tls.crt"
	ClusterMeshAdminSecretKeyName   = "tls.key"
	ClusterMeshClientSecretName     = "clustermesh-apiserver-client-certs"
	ClusterMeshClientSecretCertName = "tls.crt"
	ClusterMeshClientSecretKeyName  = "tls.key"

	ConnectivityCheckNamespace = "cilium-test"

	ConfigMapName = "cilium-config"
	Version       = "v1.9.4"

	TunnelType = "vxlan"

	WaitRetryInterval   = 2 * time.Second
	WaitWarningInterval = 10 * time.Second

	FlowWaitTimeout   = 5 * time.Second
	FlowRetryInterval = 500 * time.Millisecond
)

var OperatorLabels = map[string]string{
	"io.cilium/app": "operator",
	"name":          "cilium-operator",
}

var RelayDeploymentLabels = map[string]string{
	"k8s-app": "hubble-relay",
}

var ClusterMeshDeploymentLabels = map[string]string{
	"k8s-app": "clustermesh-apiserver",
}
