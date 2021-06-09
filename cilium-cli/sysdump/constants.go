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

	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	awsNodeDaemonSetName         = "aws-node"
	awsNodeDaemonSetNamespace    = "kube-system"
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
	awsNodeDaemonSetFileName                 = "aws-node-daemonset-<ts>.yaml"
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
	eniconfigsFileName                       = "aws-eniconfigs-<ts>.yaml"
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
	securityGroupPoliciesFileName            = "aws-securitygrouppolicies-<ts>.yaml"
	timestampPlaceholderFileName             = "<ts>"
)

const (
	ciliumBugtoolCommand = "cilium-bugtool"
	dirMode              = 0700
	fileMode             = 0600
	gopsCommand          = "/bin/gops"
	gopsPID              = "1"
	rmCommand            = "rm"
	timeFormat           = "20060102-150405"
)

var (
	awsENIConfigsGVR = schema.GroupVersionResource{
		Group:    "crd.k8s.amazonaws.com",
		Resource: "eniconfigs",
		Version:  "v1alpha1",
	}
	awsSecurityGroupPoliciesGVR = schema.GroupVersionResource{
		Group:    "vpcresources.k8s.aws",
		Resource: "securitygrouppolicies",
		Version:  "v1beta1",
	}
	ciliumBugtoolFileNameRegex = regexp.MustCompile("ARCHIVE at (.*)\n")
	gopsStats                  = []string{
		"memstats",
		"stack",
		"stats",
	}
)
