// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sysdump

import (
	"regexp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/cilium/cilium-cli/defaults"
)

const (
	awsNodeDaemonSetName               = "aws-node"
	awsNodeDaemonSetNamespace          = metav1.NamespaceSystem
	ciliumAgentContainerName           = defaults.AgentContainerName
	ciliumConfigMapName                = defaults.ConfigMapName
	ciliumEtcdSecretsSecretName        = "cilium-etcd-secrets"
	ciliumOperatorDeploymentName       = defaults.OperatorDeploymentName
	clustermeshApiserverDeploymentName = defaults.ClusterMeshDeploymentName
	hubbleContainerName                = "hubble"
	hubbleDaemonSetName                = "hubble"
	ciliumEnvoyDaemonSetName           = "cilium-envoy"
	ciliumEnvoyConfigMapName           = defaults.EnvoyConfigMapName
	hubbleRelayConfigMapName           = defaults.RelayConfigMapName
	hubbleRelayContainerName           = defaults.RelayContainerName
	hubbleRelayDeploymentName          = defaults.RelayDeploymentName
	hubbleUIDeploymentName             = defaults.HubbleUIDeploymentName
	redacted                           = "XXXXXX"
)

const (
	awsNodeDaemonSetFileName                 = "aws-node-daemonset-<ts>.yaml"
	ciliumBugtoolFileName                    = "cilium-bugtool-%s-<ts>.tar.gz"
	ciliumBPGPeeringPoliciesFileName         = "ciliumbgppeeringpolicies-<ts>.yaml"
	ciliumClusterWideNetworkPoliciesFileName = "ciliumclusterwidenetworkpolicies-<ts>.yaml"
	ciliumClusterwideEnvoyConfigsFileName    = "ciliumclusterwideenvoyconfigs-<ts>.yaml"
	ciliumConfigMapFileName                  = "cilium-configmap-<ts>.yaml"
	ciliumDaemonSetFileName                  = "cilium-daemonset-<ts>.yaml"
	ciliumEnvoyDaemonsetFileName             = "cilium-envoy-daemonset-<ts>.yaml"
	ciliumEnvoyConfigMapFileName             = "cilium-envoy-configmap-<ts>.yaml"
	ciliumIngressesFileName                  = "ciliumingresses-<ts>.yaml"
	ciliumEgressNATPoliciesFileName          = "ciliumegressnatpolicies-<ts>.yaml"
	ciliumEgressGatewayPoliciesFileName      = "ciliumegressgatewaypolicies-<ts>.yaml"
	ciliumEndpointsFileName                  = "ciliumendpoints-<ts>.yaml"
	ciliumEndpointSlicesFileName             = "ciliumendpointslices-<ts>.yaml"
	ciliumEnvoyConfigsFileName               = "ciliumenvoyconfigs-<ts>.yaml"
	ciliumEtcdSecretFileName                 = "cilium-etcd-secrets-secret-<ts>.yaml"
	ciliumExternalWorkloadFileName           = "ciliumexternalworkload-<ts>.yaml"
	ciliumIdentitiesFileName                 = "ciliumidentities-<ts>.yaml"
	ciliumCIDRGroupsFileName                 = "ciliumcidrgroups-<ts>.yaml"
	ciliumLocalRedirectPoliciesFileName      = "ciliumlocalredirectpolicies-<ts>.yaml"
	ciliumLoadBalancerIPPoolsFileName        = "ciliumloadbalancerippools-<ts>.yaml"
	ciliumLogsFileName                       = "logs-%s-%s-<ts>.log"
	ciliumPreviousLogsFileName               = "logs-%s-%s-<ts>-prev.log"
	ciliumNetworkPoliciesFileName            = "ciliumnetworkpolicies-<ts>.yaml"
	ciliumNodesFileName                      = "ciliumnodes-<ts>.yaml"
	ciliumNodeConfigsFileName                = "ciliumnodeconfigs-<ts>.yaml"
	ciliumOperatorDeploymentFileName         = "cilium-operator-deployment-<ts>.yaml"
	ciliumPodIPPoolsFileName                 = "ciliumpodippools-<ts>.yaml"
	clustermeshApiserverDeploymentFileName   = "clustermesh-apiserver-deployment-<ts>.yaml"
	cniConfigMapFileName                     = "cni-configmap-<ts>.yaml"
	cniConfigFileName                        = "cniconf-%s-%s-<ts>.txt"
	eniconfigsFileName                       = "aws-eniconfigs-<ts>.yaml"
	gopsFileName                             = "gops-%s-%s-<ts>-%s.txt"
	hubbleDaemonsetFileName                  = "hubble-daemonset-<ts>.yaml"
	hubbleFlowsFileName                      = "hubble-flows-%s-<ts>.json"
	hubbleObserveFileName                    = "hubble-observe-%s-<ts>.log"
	hubbleRelayConfigMapFileName             = "hubble-relay-configmap-<ts>.yaml"
	hubbleRelayDeploymentFileName            = "hubble-relay-deployment-<ts>.yaml"
	hubbleUIDeploymentFileName               = "hubble-ui-deployment-<ts>.yaml"
	kubernetesEndpointsFileName              = "k8s-endpoints-<ts>.yaml"
	kubernetesEventsFileName                 = "k8s-events-<ts>.yaml"
	kubernetesEventsTableFileName            = "k8s-events-<ts>.html"
	kubernetesLeasesFileName                 = "k8s-leases-<ts>.yaml"
	kubernetesNamespacesFileName             = "k8s-namespaces-<ts>.yaml"
	kubernetesNetworkPoliciesFileName        = "k8s-networkpolicies-<ts>.yaml"
	kubernetesNodesFileName                  = "k8s-nodes-<ts>.yaml"
	kubernetesPodsFileName                   = "k8s-pods-<ts>.yaml"
	kubernetesPodsSummaryFileName            = "k8s-pods-<ts>.txt"
	kubernetesServicesFileName               = "k8s-services-<ts>.yaml"
	kubernetesVersionInfoFileName            = "k8s-version-<ts>.txt"
	securityGroupPoliciesFileName            = "aws-securitygrouppolicies-<ts>.yaml"
	timestampPlaceholderFileName             = "<ts>"
	gatewayClassesFileName                   = "gatewayapi-gatewayclasses-<ts>.yaml"
	gatewaysFileName                         = "gatewayapi-gateways-<ts>.yaml"
	httpRoutesFileName                       = "gatewayapi-httproutes-<ts>.yaml"
	tlsRoutesFileName                        = "gatewayapi-tlsroutes-<ts>.yaml"
	grpcRoutesFileName                       = "gatewayapi-grpcroutes-<ts>.yaml"
	tcpRoutesFileName                        = "gatewayapi-tcroutes-<ts>.yaml"
	udpRoutesFileName                        = "gatewayapi-udproutes-<ts>.yaml"
	referenceGrantsFileName                  = "gatewayapi-referencegrants-<ts>.yaml"
	ingressClassesFileName                   = "ingressclasses-<ts>.yaml"
)

const (
	ciliumBugtoolCommand = "cilium-bugtool"
	dirMode              = 0700
	fileMode             = 0600
	gopsCommand          = "/bin/gops"
	gopsPID              = "1"
	rmCommand            = "rm"
	timeFormat           = "20060102-150405"
	lsCommand            = "/usr/bin/ls"
	catCommand           = "/usr/bin/cat"
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
	k8sLeases = schema.GroupVersionResource{
		Group:    "coordination.k8s.io",
		Resource: "leases",
		Version:  "v1",
	}
	ciliumBugtoolFileNameRegex = regexp.MustCompile("GZIP at (.*)\n")
	gopsRegexp                 = regexp.MustCompile(`^(?P<pid>\d+).*\*`)
	gopsStats                  = []string{
		"memstats",
		"stack",
		"stats",
	}
	gopsProfiling = []string{
		"pprof-heap",
		"pprof-cpu",
	}

	// Gateway API resource group versions used for sysdumping these
	gatewayClass = schema.GroupVersionResource{
		Group:    "gateway.networking.k8s.io",
		Resource: "gatewayclasses",
		Version:  "v1beta1",
	}

	gateway = schema.GroupVersionResource{
		Group:    "gateway.networking.k8s.io",
		Resource: "gateways",
		Version:  "v1beta1",
	}

	referenceGrant = schema.GroupVersionResource{
		Group:    "gateway.networking.k8s.io",
		Resource: "referencegrants",
		Version:  "v1alpha2",
	}

	httpRoute = schema.GroupVersionResource{
		Group:    "gateway.networking.k8s.io",
		Resource: "httproutes",
		Version:  "v1beta1",
	}

	tlsRoute = schema.GroupVersionResource{
		Group:    "gateway.networking.k8s.io",
		Resource: "tlsroutes",
		Version:  "v1alpha2",
	}

	tcpRoute = schema.GroupVersionResource{
		Group:    "gateway.networking.k8s.io",
		Resource: "tcproutes",
		Version:  "v1alpha2",
	}

	udpRoute = schema.GroupVersionResource{
		Group:    "gateway.networking.k8s.io",
		Resource: "udproutes",
		Version:  "v1alpha2",
	}

	grpcRoute = schema.GroupVersionResource{
		Group:    "gateway.networking.k8s.io",
		Resource: "grpcroutes",
		Version:  "v1alpha2",
	}
)
