// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package sysdump

import (
	"regexp"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	awsNodeDaemonSetName               = "aws-node"
	awsNodeDaemonSetNamespace          = "kube-system"
	ciliumAgentContainerName           = "cilium-agent"
	ciliumConfigConfigMapName          = "cilium-config"
	ciliumDaemonSetName                = "cilium"
	ciliumEtcdSecretsSecretName        = "cilium-etcd-secrets"
	ciliumOperatorDeploymentName       = "cilium-operator"
	clustermeshApiserverDeploymentName = "clustermesh-apiserver"
	hubbleContainerName                = "hubble"
	hubbleDaemonSetName                = "hubble"
	hubbleRelayContainerName           = "hubble-relay"
	hubbleRelayDeploymentName          = "hubble-relay"
	hubbleUIDeploymentName             = "hubble-ui"
	redacted                           = "XXXXXX"
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
	clustermeshApiserverDeploymentFileName   = "clustermesh-apiserver-deployment-<ts>.yaml"
	eniconfigsFileName                       = "aws-eniconfigs-<ts>.yaml"
	gopsFileName                             = "gops-%s-%s-<ts>-%s.txt"
	hubbleDaemonsetFileName                  = "hubble-daemonset-<ts>.yaml"
	hubbleFlowsFileName                      = "hubble-flows-%s-<ts>.json"
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
