// Copyright 2021 Authors of Cilium
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

package sysdump

import (
	"regexp"
)

const (
	ciliumAgentContainerName     = "cilium-agent"
	ciliumConfigConfigMapName    = "cilium-config"
	ciliumDaemonSetName          = "cilium"
	ciliumEtcdSecretsSecretName  = "cilium-etcd-secrets"
	ciliumOperatorDeploymentName = "cilium-operator"
	hubbleContainerName          = "hubble"
	hubbleDaemonSetName          = "hubble"
	hubbleRelayContainerName     = "hubble-relay"
	hubbleRelayDeploymentName    = "hubble-relay"
	hubbleUIDeploymentName       = "hubble-ui"
	redacted                     = "XXXXXX"
)

const (
	ciliumBugtoolFileName                    = "cilium-bugtool-%s-<ts>.tar"
	ciliumClusterWideNetworkPoliciesFileName = "ciliumclusterwidenetworkpolicies-<ts>.yaml"
	ciliumConfigMapFileName                  = "cilium-config-configmap-<ts>.yaml"
	ciliumDaemonSetFileName                  = "cilium-daemonset-<ts>.yaml"
	ciliumEndpointsFileName                  = "ciliumendpoints-<ts>.yaml"
	ciliumEtcdSecretFileName                 = "cilium-etcd-secrets-secret-<ts>.yaml"
	ciliumIdentitiesFileName                 = "ciliumidentities-<ts>.yaml"
	ciliumLogsFileName                       = "logs-%s-%s-<ts>.log"
	ciliumPreviousLogsFileName               = "logs-%s-%s-<ts>-prev.log"
	ciliumNetworkPoliciesFileName            = "ciliumnetworkpolicies-<ts>.yaml"
	ciliumNodesFileName                      = "ciliumnodes-<ts>.yaml"
	ciliumOperatorDeploymentFileName         = "cilium-operator-deployment-<ts>.yaml"
	gopsFileName                             = "gops-%s-%s-<ts>-%s.txt"
	hubbleDaemonsetFileName                  = "hubble-daemonset-<ts>.yaml"
	hubbleRelayDeploymentFileName            = "hubble-relay-deployment-<ts>.yaml"
	hubbleUIDeploymentFileName               = "hubble-ui-deployment-<ts>.yaml"
	kubernetesEventsFileName                 = "k8s-events-<ts>.yaml"
	kubernetesNamespacesFileName             = "k8s-namespaces-<ts>.yaml"
	kubernetesNetworkPoliciesFileName        = "k8s-networkpolicies-<ts>.yaml"
	kubernetesNodesFileName                  = "k8s-nodes-<ts>.yaml"
	kubernetesPodsFileName                   = "k8s-pods-<ts>.yaml"
	kubernetesPodsSummaryFileName            = "k8s-pods-<ts>.txt"
	kubernetesServicesFileName               = "k8s-services-<ts>.yaml"
	kubernetesVersionInfoFileName            = "k8s-version-<ts>.txt"
	timestampPlaceholderFileName             = "<ts>"
)

const (
	dirMode    = 0700
	fileMode   = 0600
	timeFormat = "20060102-150405"
)

var (
	ciliumBugtoolFileNameRegex = regexp.MustCompile("ARCHIVE at (.*)\n")
	ciliumBugtoolCommand       = "cilium-bugtool"
	gopsCommand                = "/bin/gops"
	gopsPID                    = "1"
	gopsStats                  = []string{
		"memstats",
		"stack",
		"stats",
	}
	rmCommand = "rm"
)
