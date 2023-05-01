// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"time"

	"github.com/spf13/viper"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "option")

var IngressLBAnnotationsDefault = []string{"service.beta.kubernetes.io", "service.kubernetes.io", "cloud.google.com"}

const (
	// EndpointGCIntervalDefault is the default time for the CEP GC
	EndpointGCIntervalDefault = 5 * time.Minute

	// PrometheusServeAddr is the default server address for operator metrics
	PrometheusServeAddr = ":9963"

	// CESMaxCEPsInCESDefault is the maximum number of cilium endpoints allowed in a CES
	CESMaxCEPsInCESDefault = 100

	// CESSlicingModeDefault is default method for grouping CEP in a CES.
	CESSlicingModeDefault = "cesSliceModeIdentity"

	// CNPStatusCleanupQPSDefault is the default rate for the CNP NodeStatus updates GC.
	CNPStatusCleanupQPSDefault = 10

	// CNPStatusCleanupBurstDefault is the default maximum burst for the CNP NodeStatus updates GC.
	CNPStatusCleanupBurstDefault = 20

	// PprofAddressOperator is the default value for pprof in the operator
	PprofAddressOperator = "localhost"

	// PprofPortOperator is the default value for pprof in the operator
	PprofPortOperator = 6061

	// DefaultProxyIdleTimeoutSeconds is the default value for the proxy idle timeout
	DefaultProxyIdleTimeoutSeconds = 60
)

const (
	// BGPAnnounceLBIP announces service IPs of type LoadBalancer via BGP beta (deprecated)
	BGPAnnounceLBIP = "bgp-announce-lb-ip"

	// BGPConfigPath is the file path to the BGP configuration. It is
	// compatible with MetalLB's configuration.
	BGPConfigPath = "bgp-config-path"

	// CNPNodeStatusGCInterval is the GC interval for nodes which have been
	// removed from the cluster in CiliumNetworkPolicy and
	// CiliumClusterwideNetworkPolicy Status.
	CNPNodeStatusGCInterval = "cnp-node-status-gc-interval"

	// CNPStatusUpdateInterval is the interval between status updates
	// being sent to the K8s apiserver for a given CNP.
	CNPStatusUpdateInterval = "cnp-status-update-interval"

	// SkipCNPStatusStartupClean specifies if the cleanup of all the CNP
	// NodeStatus updates at startup must be skipped.
	SkipCNPStatusStartupClean = "skip-cnp-status-startup-clean"

	// CNPStatusCleanupQPS is the rate at which the cleanup operation of the status
	// nodes updates in CNPs is carried out. It is expressed as queries per second,
	// and for each query a single CNP status update will be deleted.
	CNPStatusCleanupQPS = "cnp-status-cleanup-qps"

	// CNPStatusCleanupBurst is the maximum burst of queries allowed for the cleanup
	// operation of the status nodes updates in CNPs.
	CNPStatusCleanupBurst = "cnp-status-cleanup-burst"

	// EnableMetrics enables prometheus metrics.
	EnableMetrics = "enable-metrics"

	// EndpointGCInterval is the interval between attempts of the CEP GC
	// controller.
	// Note that only one node per cluster should run this, and most iterations
	// will simply return.
	EndpointGCInterval = "cilium-endpoint-gc-interval"

	// NodesGCInterval is the duration for which the cilium nodes are GC.
	NodesGCInterval = "nodes-gc-interval"

	// OperatorPrometheusServeAddr IP:Port on which to serve prometheus
	// metrics (pass ":Port" to bind on all interfaces, "" is off).
	OperatorPrometheusServeAddr = "operator-prometheus-serve-addr"

	// SyncK8sServices synchronizes k8s services into the kvstore
	SyncK8sServices = "synchronize-k8s-services"

	// SyncK8sNodes synchronizes k8s nodes into the kvstore
	SyncK8sNodes = "synchronize-k8s-nodes"

	// UnmanagedPodWatcherInterval is the interval to check for unmanaged kube-dns pods (0 to disable)
	UnmanagedPodWatcherInterval = "unmanaged-pod-watcher-interval"

	// IPAM options

	// IPAMAPIBurst is the burst value allowed when accessing external IPAM APIs
	IPAMAPIBurst = "limit-ipam-api-burst"

	// IPAMAPIQPSLimit is the queries per second limit when accessing external IPAM APIs
	IPAMAPIQPSLimit = "limit-ipam-api-qps"

	// IPAMSubnetsIDs are optional subnets IDs used to filter subnets and interfaces listing
	IPAMSubnetsIDs = "subnet-ids-filter"

	// IPAMSubnetsTags are optional tags used to filter subnets, and interfaces within those subnets
	IPAMSubnetsTags = "subnet-tags-filter"

	// IPAMInstanceTagFilter are optional tags used to filter instances for ENI discovery ; only used with AWS IPAM mode for now
	IPAMInstanceTags = "instance-tags-filter"

	// IPAMMultiPoolMap are IP pool definitions used for the multi-pool IPAM mode.
	IPAMMultiPoolMap = "multi-pool-map"

	// ClusterPoolIPv4CIDR is the cluster's IPv4 CIDR to allocate
	// individual PodCIDR ranges from when using the ClusterPool ipam mode.
	ClusterPoolIPv4CIDR = "cluster-pool-ipv4-cidr"

	// ClusterPoolIPv6CIDR is the cluster's IPv6 CIDR to allocate
	// individual PodCIDR ranges from when using the ClusterPool ipam mode.
	ClusterPoolIPv6CIDR = "cluster-pool-ipv6-cidr"

	// NodeCIDRMaskSizeIPv4 is the IPv4 podCIDR mask size that will be used
	// per node.
	NodeCIDRMaskSizeIPv4 = "cluster-pool-ipv4-mask-size"

	// NodeCIDRMaskSizeIPv6 is the IPv6 podCIDR mask size that will be used
	// per node.
	NodeCIDRMaskSizeIPv6 = "cluster-pool-ipv6-mask-size"

	// AWS options

	// AWSInstanceLimitMapping allows overwirting AWS instance limits defined in
	// pkg/aws/eni/limits.go
	// e.g. {"a1.medium": "2,4,4", "a2.custom2": "4,5,6"}
	AWSInstanceLimitMapping = "aws-instance-limit-mapping"

	// AWSReleaseExcessIPs allows releasing excess free IP addresses from ENI.
	// Enabling this option reduces waste of IP addresses but may increase
	// the number of API calls to AWS EC2 service.
	AWSReleaseExcessIPs = "aws-release-excess-ips"

	// ExcessIPReleaseDelay controls how long operator would wait before an IP previously marked as excess is released.
	// Defaults to 180 secs
	ExcessIPReleaseDelay = "excess-ip-release-delay"

	// AWSEnablePrefixDelegation allows operator to allocate prefixes to ENIs on nitro instances instead of individual
	// IP addresses. Allows for increased pod density on nodes.
	AWSEnablePrefixDelegation = "aws-enable-prefix-delegation"

	// ENITags are the tags that will be added to every ENI created by the
	// AWS ENI IPAM.
	ENITags = "eni-tags"

	// ENIGarbageCollectionTags is a tag that will be added to every ENI
	// created by the AWS ENI IPAM.
	// Any stale and unattached ENIs with this tag will be garbage
	// collected by the operator.
	ENIGarbageCollectionTags = "eni-gc-tags"

	// ENIGarbageCollectionInterval defines the interval of ENI GC
	ENIGarbageCollectionInterval = "eni-gc-interval"

	// ParallelAllocWorkers specifies the number of parallel workers to be used for IPAM allocation
	ParallelAllocWorkers = "parallel-alloc-workers"

	// UpdateEC2AdapterLimitViaAPI configures the operator to use the EC2
	// API to fill out the instancetype to adapter limit mapping.
	UpdateEC2AdapterLimitViaAPI = "update-ec2-adapter-limit-via-api"

	// EC2APIEndpoint is the custom API endpoint to use for the EC2 AWS service,
	// e.g. "ec2-fips.us-west-1.amazonaws.com" to use a FIPS endpoint in the us-west-1 region.
	EC2APIEndpoint = "ec2-api-endpoint"

	// AWSUsePrimaryAddress specifies whether an interface's primary address should be available for allocations on
	// node
	AWSUsePrimaryAddress = "aws-use-primary-address"

	// Azure options

	// AzureSubscriptionID is the subscription ID to use when accessing the Azure API
	AzureSubscriptionID = "azure-subscription-id"

	// AzureResourceGroup is the resource group of the nodes used for the cluster
	AzureResourceGroup = "azure-resource-group"

	// AzureUserAssignedIdentityID is the id of the user assigned identity used
	// for retrieving Azure API credentials
	AzureUserAssignedIdentityID = "azure-user-assigned-identity-id"

	// AzureUsePrimaryAddress specifies whether we should use or ignore the interface's
	// primary IPConfiguration
	AzureUsePrimaryAddress = "azure-use-primary-address"

	// LeaderElectionLeaseDuration is the duration that non-leader candidates will wait to
	// force acquire leadership
	LeaderElectionLeaseDuration = "leader-election-lease-duration"

	// LeaderElectionRenewDeadline is the duration that the current acting master in HA deployment
	// will retry refreshing leadership before giving up the lock.
	LeaderElectionRenewDeadline = "leader-election-renew-deadline"

	// LeaderElectionRetryPeriod is the duration the LeaderElector clients should wait between
	// tries of the actions in operator HA deployment.
	LeaderElectionRetryPeriod = "leader-election-retry-period"

	// AlibabaCloud options

	// AlibabaCloudVPCID allows user to specific vpc
	AlibabaCloudVPCID = "alibaba-cloud-vpc-id"

	// AlibabaCloudReleaseExcessIPs allows releasing excess free IP addresses from ENI.
	// Enabling this option reduces waste of IP addresses but may increase
	// the number of API calls to AlibabaCloud ECS service.
	AlibabaCloudReleaseExcessIPs = "alibaba-cloud-release-excess-ips"

	// CiliumEndpointSlice options

	// CESMaxCEPsInCES is the maximum number of cilium endpoints allowed in single
	// a CiliumEndpointSlice resource.
	CESMaxCEPsInCES = "ces-max-ciliumendpoints-per-ces"

	// CESSlicingMode instructs how CEPs are grouped in a CES.
	CESSlicingMode = "ces-slice-mode"

	// LoadBalancerL7 enables loadbalancer capabilities for services via envoy proxy
	LoadBalancerL7 = "loadbalancer-l7"

	// LoadBalancerL7Ports is a list of service ports that will be automatically redirected to backend.
	LoadBalancerL7Ports = "loadbalancer-l7-ports"

	// LoadBalancerL7Algorithm is a default LB algorithm for services that do not specify related annotation
	LoadBalancerL7Algorithm = "loadbalancer-l7-algorithm"

	// EnableIngressController enables cilium ingress controller
	// This must be enabled along with enable-envoy-config in cilium agent.
	EnableIngressController = "enable-ingress-controller"

	// EnforceIngressHttps enforces https for host having matching TLS host in Ingress.
	// Incoming traffic to http listener will return 308 http error code with respective location in header.
	EnforceIngressHttps = "enforce-ingress-https"

	// EnableIngressSecretsSync enables fan-in TLS secrets from multiple namespaces to singular namespace (specified
	// by ingress-secrets-namespace flag
	EnableIngressSecretsSync = "enable-ingress-secrets-sync"

	// EnableGatewayAPISecretsSync enables fan-in TLS secrets from multiple namespaces to singular namespace (specified
	// by gateway-api-secrets-namespace flag
	EnableGatewayAPISecretsSync = "enable-gateway-api-secrets-sync"

	// IngressSecretsNamespace is the namespace having tls secrets used by Ingress and CEC.
	IngressSecretsNamespace = "ingress-secrets-namespace"

	// GatewayAPISecretsNamespace is the namespace having tls secrets used by GatewayAPI and CEC.
	GatewayAPISecretsNamespace = "gateway-api-secrets-namespace"

	// ProxyIdleTimeoutSeconds is the idle timeout for proxy connections to upstream clusters
	ProxyIdleTimeoutSeconds = "proxy-idle-timeout-seconds"

	// EnableGatewayAPI enables support of Gateway API
	// This must be enabled along with enable-envoy-config in cilium agent.
	EnableGatewayAPI = "enable-gateway-api"

	// CiliumK8sNamespace is the namespace where Cilium pods are running.
	CiliumK8sNamespace = "cilium-pod-namespace"

	// CiliumPodLabels specifies the pod labels that Cilium pods is running
	// with.
	CiliumPodLabels = "cilium-pod-labels"

	// RemoveCiliumNodeTaints is the flag to define if the Cilium node taint
	// should be removed in Kubernetes nodes.
	RemoveCiliumNodeTaints = "remove-cilium-node-taints"

	// SetCiliumNodeTaints is whether or not to taint nodes that do not have
	// a running Cilium instance.
	SetCiliumNodeTaints = "set-cilium-node-taints"

	// SetCiliumIsUpCondition sets the CiliumIsUp node condition in Kubernetes
	// nodes.
	SetCiliumIsUpCondition = "set-cilium-is-up-condition"

	// IngressLBAnnotationPrefixes are the annotations which are needed to propagate
	// from Ingress to the Load Balancer
	IngressLBAnnotationPrefixes = "ingress-lb-annotation-prefixes"

	// IngressSharedLBServiceName is the name of shared LB service name for Ingress.
	IngressSharedLBServiceName = "ingress-shared-lb-service-name"

	// IngressDefaultLoadbalancerMode is the default loadbalancer mode for Ingress.
	// Applicable values: dedicated, shared
	IngressDefaultLoadbalancerMode = "ingress-default-lb-mode"

	// PodRestartSelector specify the labels contained in the pod that needs to be restarted before the node can be de-stained
	// default values: k8s-app=kube-dns
	PodRestartSelector = "pod-restart-selector"
)

// OperatorConfig is the configuration used by the operator.
type OperatorConfig struct {
	// CNPNodeStatusGCInterval is the GC interval for nodes which have been
	// removed from the cluster in CiliumNetworkPolicy and
	// CiliumClusterwideNetworkPolicy Status.
	CNPNodeStatusGCInterval time.Duration

	// CNPStatusUpdateInterval is the interval between status updates
	// being sent to the K8s apiserver for a given CNP.
	CNPStatusUpdateInterval time.Duration

	// NodesGCInterval is the GC interval for CiliumNodes
	NodesGCInterval time.Duration

	// SkipCNPStatusStartupClean disables the cleanup of all the CNP
	// NodeStatus updates at startup.
	SkipCNPStatusStartupClean bool

	// CNPStatusCleanupQPS is the rate at which the cleanup operation of the status
	// nodes updates in CNPs is carried out. It is expressed as queries per second,
	// and for each query a single CNP status update will be deleted.
	CNPStatusCleanupQPS float64

	// CNPStatusCleanupBurst is the maximum burst of queries allowed for the cleanup
	// operation of the status nodes updates in CNPs.
	CNPStatusCleanupBurst int

	// EnableMetrics enables prometheus metrics.
	EnableMetrics bool

	// EndpointGCInterval is the interval between attempts of the CEP GC
	// controller.
	// Note that only one node per cluster should run this, and most iterations
	// will simply return.
	EndpointGCInterval time.Duration

	OperatorPrometheusServeAddr string

	// SyncK8sServices synchronizes k8s services into the kvstore
	SyncK8sServices bool

	// SyncK8sNodes synchronizes k8s nodes into the kvstore
	SyncK8sNodes bool

	// UnmanagedPodWatcherInterval is the interval to check for unmanaged kube-dns pods (0 to disable)
	UnmanagedPodWatcherInterval int

	// LeaderElectionLeaseDuration is the duration that non-leader candidates will wait to
	// force acquire leadership in Cilium Operator HA deployment.
	LeaderElectionLeaseDuration time.Duration

	// LeaderElectionRenewDeadline is the duration that the current acting master in HA deployment
	// will retry refreshing leadership in before giving up the lock.
	LeaderElectionRenewDeadline time.Duration

	// LeaderElectionRetryPeriod is the duration that LeaderElector clients should wait between
	// retries of the actions in operator HA deployment.
	LeaderElectionRetryPeriod time.Duration

	// BGPAnnounceLBIP announces service IPs of type LoadBalancer via BGP beta (deprecated)
	BGPAnnounceLBIP bool

	// BGPConfigPath is the file path to the BGP configuration. It is
	// compatible with MetalLB's configuration.
	BGPConfigPath string

	// IPAM options

	// IPAMAPIBurst is the burst value allowed when accessing external IPAM APIs
	IPAMAPIBurst int

	// IPAMAPIQPSLimit is the queries per second limit when accessing external IPAM APIs
	IPAMAPIQPSLimit float64

	// IPAMSubnetsIDs are optional subnets IDs used to filter subnets and interfaces listing
	IPAMSubnetsIDs []string

	// IPAMSubnetsTags are optional tags used to filter subnets, and interfaces within those subnets
	IPAMSubnetsTags map[string]string

	// IPAMUInstanceTags are optional tags used to filter AWS EC2 instances, and interfaces (ENI) attached to them
	IPAMInstanceTags map[string]string

	// IPAM Operator options

	// ClusterPoolIPv4CIDR is the cluster IPv4 podCIDR that should be used to
	// allocate pods in the node.
	ClusterPoolIPv4CIDR []string

	// ClusterPoolIPv6CIDR is the cluster IPv6 podCIDR that should be used to
	// allocate pods in the node.
	ClusterPoolIPv6CIDR []string

	// NodeCIDRMaskSizeIPv4 is the IPv4 podCIDR mask size that will be used
	// per node.
	NodeCIDRMaskSizeIPv4 int

	// NodeCIDRMaskSizeIPv6 is the IPv6 podCIDR mask size that will be used
	// per node.
	NodeCIDRMaskSizeIPv6 int

	// IPAMMultiPoolMap are IP pool definitions used for the multi-pool IPAM mode.
	IPAMMultiPoolMap map[string]string

	// AWS options

	// ENITags are the tags that will be added to every ENI created by the AWS ENI IPAM
	ENITags map[string]string

	// ENIGarbageCollectionTags is a tag that will be added to every ENI
	// created by the AWS ENI IPAM.
	// Any stale and unattached ENIs with this tag will be garbage
	// collected by the operator.
	ENIGarbageCollectionTags map[string]string

	// ENIGarbageCollectionInterval defines the interval of ENI GC
	ENIGarbageCollectionInterval time.Duration

	// ParallelAllocWorkers specifies the number of parallel workers to be used for accessing cloud provider APIs .
	ParallelAllocWorkers int64

	// AWSInstanceLimitMapping allows overwriting AWS instance limits defined in
	// pkg/aws/eni/limits.go
	// e.g. {"a1.medium": "2,4,4", "a2.custom2": "4,5,6"}
	AWSInstanceLimitMapping map[string]string

	// AWSReleaseExcessIps allows releasing excess free IP addresses from ENI.
	// Enabling this option reduces waste of IP addresses but may increase
	// the number of API calls to AWS EC2 service.
	AWSReleaseExcessIPs bool

	// AWSEnablePrefixDelegation allows operator to allocate prefixes to ENIs on nitro instances instead of individual
	// IP addresses. Allows for increased pod density on nodes.
	AWSEnablePrefixDelegation bool

	// AWSUsePrimaryAddress specifies whether an interface's primary address should be available for allocations on
	// node
	AWSUsePrimaryAddress bool

	// UpdateEC2AdapterLimitViaAPI configures the operator to use the EC2 API to fill out the
	// instancetype to adapter limit mapping.
	UpdateEC2AdapterLimitViaAPI bool

	// ExcessIPReleaseDelay controls how long operator would wait before an IP previously marked as excess is released.
	// Defaults to 180 secs
	ExcessIPReleaseDelay int

	// EC2APIEndpoint is the custom API endpoint to use for the EC2 AWS service,
	// e.g. "ec2-fips.us-west-1.amazonaws.com" to use a FIPS endpoint in the us-west-1 region.
	EC2APIEndpoint string

	// Azure options

	// AzureSubscriptionID is the subscription ID to use when accessing the Azure API
	AzureSubscriptionID string

	// AzureResourceGroup is the resource group of the nodes used for the cluster
	AzureResourceGroup string

	// AzureUserAssignedIdentityID is the id of the user assigned identity used
	// for retrieving Azure API credentials
	AzureUserAssignedIdentityID string

	// AzureUsePrimaryAddress specify wether we should use or ignore the interface's
	// primary IPConfiguration
	AzureUsePrimaryAddress bool

	// AlibabaCloud options

	// AlibabaCloudVPCID allow user to specific vpc
	AlibabaCloudVPCID string

	// AlibabaCloudReleaseExcessIPs allows releasing excess free IP addresses from ENI.
	// Enabling this option reduces waste of IP addresses but may increase
	// the number of API calls to AlibabaCloud ECS service.
	AlibabaCloudReleaseExcessIPs bool

	// CiliumEndpointSlice options

	// CESMaxCEPsInCES is the maximum number of CiliumEndpoints allowed in single
	// a CiliumEndpointSlice resource.
	// The default value of maximum CiliumEndpoints allowed in a CiliumEndpointSlice resource is 100.
	CESMaxCEPsInCES int

	// CESSlicingMode instructs how CEPs are grouped in a CES.
	CESSlicingMode string

	// LoadBalancerL7 enables loadbalancer capabilities for services.
	LoadBalancerL7 string

	// EnvoyLoadBalancerPorts is a list of service ports that will be automatically redirected to Envoy
	LoadBalancerL7Ports []string

	// LoadBalancerL7Algorithm is a default LB algorithm for services that do not specify related annotation
	LoadBalancerL7Algorithm string

	// EnableIngressController enables cilium ingress controller
	EnableIngressController bool

	// EnableGatewayAPI enables support of Gateway API
	EnableGatewayAPI bool

	// EnforceIngressHTTPS enforces https if required
	EnforceIngressHTTPS bool

	// EnableIngressSecretsSync enables background TLS secret sync for Ingress
	EnableIngressSecretsSync bool

	// EnableGatewayAPISecretsSync enables background TLS secret sync for Gateway API
	EnableGatewayAPISecretsSync bool

	// IngressSecretsNamespace is the namespace having tls secrets used by CEC for Ingress.
	IngressSecretsNamespace string

	// GatewayAPISecretsNamespace is the namespace having tls secrets used by CEC for Gateway API.
	GatewayAPISecretsNamespace string

	// ProxyIdleTimeoutSeconds is the idle timeout for the proxy to upstream cluster
	ProxyIdleTimeoutSeconds int

	// CiliumK8sNamespace is the namespace where Cilium pods are running.
	CiliumK8sNamespace string

	// CiliumPodLabels specifies the pod labels that Cilium pods is running
	// with.
	CiliumPodLabels string

	// RemoveCiliumNodeTaints is the flag to define if the Cilium node taint
	// should be removed in Kubernetes nodes.
	RemoveCiliumNodeTaints bool

	// SetCiliumNodeTaints is whether or not to set taints on nodes that do not
	// have a running Cilium pod.
	SetCiliumNodeTaints bool

	// SetCiliumIsUpCondition sets the CiliumIsUp node condition in Kubernetes
	// nodes.
	SetCiliumIsUpCondition bool

	// IngressLBAnnotationPrefixes IngressLBAnnotations are the annotation prefixes,
	// which are used to filter annotations to propagate from Ingress to the Load Balancer
	IngressLBAnnotationPrefixes []string

	// IngressSharedLBServiceName is the name of shared LB service name for Ingress.
	IngressSharedLBServiceName string

	// IngressDefaultLoadbalancerMode is the default loadbalancer mode for Ingress.
	// Applicable values: dedicated, shared
	IngressDefaultLoadbalancerMode string

	// PodRestartSelector specify the labels contained in the pod that needs to be restarted before the node can be de-stained
	PodRestartSelector string
}

// Populate sets all options with the values from viper.
func (c *OperatorConfig) Populate(vp *viper.Viper) {
	c.CNPNodeStatusGCInterval = vp.GetDuration(CNPNodeStatusGCInterval)
	c.CNPStatusUpdateInterval = vp.GetDuration(CNPStatusUpdateInterval)
	c.NodesGCInterval = vp.GetDuration(NodesGCInterval)
	c.SkipCNPStatusStartupClean = vp.GetBool(SkipCNPStatusStartupClean)
	c.CNPStatusCleanupQPS = vp.GetFloat64(CNPStatusCleanupQPS)
	c.CNPStatusCleanupBurst = vp.GetInt(CNPStatusCleanupBurst)
	c.EnableMetrics = vp.GetBool(EnableMetrics)
	c.EndpointGCInterval = vp.GetDuration(EndpointGCInterval)
	c.OperatorPrometheusServeAddr = vp.GetString(OperatorPrometheusServeAddr)
	c.SyncK8sServices = vp.GetBool(SyncK8sServices)
	c.SyncK8sNodes = vp.GetBool(SyncK8sNodes)
	c.UnmanagedPodWatcherInterval = vp.GetInt(UnmanagedPodWatcherInterval)
	c.NodeCIDRMaskSizeIPv4 = vp.GetInt(NodeCIDRMaskSizeIPv4)
	c.NodeCIDRMaskSizeIPv6 = vp.GetInt(NodeCIDRMaskSizeIPv6)
	c.ClusterPoolIPv4CIDR = vp.GetStringSlice(ClusterPoolIPv4CIDR)
	c.ClusterPoolIPv6CIDR = vp.GetStringSlice(ClusterPoolIPv6CIDR)
	c.LeaderElectionLeaseDuration = vp.GetDuration(LeaderElectionLeaseDuration)
	c.LeaderElectionRenewDeadline = vp.GetDuration(LeaderElectionRenewDeadline)
	c.LeaderElectionRetryPeriod = vp.GetDuration(LeaderElectionRetryPeriod)
	c.BGPAnnounceLBIP = vp.GetBool(BGPAnnounceLBIP)
	c.BGPConfigPath = vp.GetString(BGPConfigPath)
	c.LoadBalancerL7 = vp.GetString(LoadBalancerL7)
	c.LoadBalancerL7Ports = vp.GetStringSlice(LoadBalancerL7Ports)
	c.LoadBalancerL7Algorithm = vp.GetString(LoadBalancerL7Algorithm)
	c.EnableIngressController = vp.GetBool(EnableIngressController)
	c.EnableGatewayAPI = vp.GetBool(EnableGatewayAPI)
	c.EnforceIngressHTTPS = vp.GetBool(EnforceIngressHttps)
	c.IngressSecretsNamespace = vp.GetString(IngressSecretsNamespace)
	c.GatewayAPISecretsNamespace = vp.GetString(GatewayAPISecretsNamespace)
	c.ProxyIdleTimeoutSeconds = vp.GetInt(ProxyIdleTimeoutSeconds)
	if c.ProxyIdleTimeoutSeconds == 0 {
		c.ProxyIdleTimeoutSeconds = DefaultProxyIdleTimeoutSeconds
	}
	c.EnableIngressSecretsSync = vp.GetBool(EnableIngressSecretsSync)
	c.EnableGatewayAPISecretsSync = vp.GetBool(EnableGatewayAPISecretsSync)
	c.CiliumPodLabels = vp.GetString(CiliumPodLabels)
	c.RemoveCiliumNodeTaints = vp.GetBool(RemoveCiliumNodeTaints)
	c.SetCiliumNodeTaints = vp.GetBool(SetCiliumNodeTaints)
	c.SetCiliumIsUpCondition = vp.GetBool(SetCiliumIsUpCondition)
	c.IngressLBAnnotationPrefixes = vp.GetStringSlice(IngressLBAnnotationPrefixes)
	c.IngressSharedLBServiceName = vp.GetString(IngressSharedLBServiceName)
	c.IngressDefaultLoadbalancerMode = vp.GetString(IngressDefaultLoadbalancerMode)
	c.PodRestartSelector = vp.GetString(PodRestartSelector)

	c.CiliumK8sNamespace = vp.GetString(CiliumK8sNamespace)

	if c.CiliumK8sNamespace == "" {
		if option.Config.K8sNamespace == "" {
			c.CiliumK8sNamespace = metav1.NamespaceDefault
		} else {
			c.CiliumK8sNamespace = option.Config.K8sNamespace
		}
	}

	if c.BGPAnnounceLBIP {
		c.SyncK8sServices = true
		log.Infof("Auto-set %q to `true` because BGP support requires synchronizing services.",
			SyncK8sServices)
	}

	// IPAM options

	c.IPAMAPIQPSLimit = vp.GetFloat64(IPAMAPIQPSLimit)
	c.IPAMAPIBurst = vp.GetInt(IPAMAPIBurst)
	c.ParallelAllocWorkers = vp.GetInt64(ParallelAllocWorkers)

	// AWS options

	c.AWSReleaseExcessIPs = vp.GetBool(AWSReleaseExcessIPs)
	c.AWSEnablePrefixDelegation = vp.GetBool(AWSEnablePrefixDelegation)
	c.AWSUsePrimaryAddress = vp.GetBool(AWSUsePrimaryAddress)
	c.UpdateEC2AdapterLimitViaAPI = vp.GetBool(UpdateEC2AdapterLimitViaAPI)
	c.EC2APIEndpoint = vp.GetString(EC2APIEndpoint)
	c.ExcessIPReleaseDelay = vp.GetInt(ExcessIPReleaseDelay)
	c.ENIGarbageCollectionInterval = vp.GetDuration(ENIGarbageCollectionInterval)

	// Azure options

	c.AzureSubscriptionID = vp.GetString(AzureSubscriptionID)
	c.AzureResourceGroup = vp.GetString(AzureResourceGroup)
	c.AzureUsePrimaryAddress = vp.GetBool(AzureUsePrimaryAddress)
	c.AzureUserAssignedIdentityID = vp.GetString(AzureUserAssignedIdentityID)

	// AlibabaCloud options

	c.AlibabaCloudVPCID = vp.GetString(AlibabaCloudVPCID)
	c.AlibabaCloudReleaseExcessIPs = vp.GetBool(AlibabaCloudReleaseExcessIPs)

	// CiliumEndpointSlice options
	c.CESMaxCEPsInCES = vp.GetInt(CESMaxCEPsInCES)
	c.CESSlicingMode = vp.GetString(CESSlicingMode)

	// Option maps and slices

	if m := vp.GetStringSlice(IPAMSubnetsIDs); len(m) != 0 {
		c.IPAMSubnetsIDs = m
	}

	if m, err := command.GetStringMapStringE(vp, IPAMSubnetsTags); err != nil {
		log.Fatalf("unable to parse %s: %s", IPAMSubnetsTags, err)
	} else {
		c.IPAMSubnetsTags = m
	}

	if m, err := command.GetStringMapStringE(vp, IPAMInstanceTags); err != nil {
		log.Fatalf("unable to parse %s: %s", IPAMInstanceTags, err)
	} else {
		c.IPAMInstanceTags = m
	}

	if m, err := command.GetStringMapStringE(vp, AWSInstanceLimitMapping); err != nil {
		log.Fatalf("unable to parse %s: %s", AWSInstanceLimitMapping, err)
	} else {
		c.AWSInstanceLimitMapping = m
	}

	if m, err := command.GetStringMapStringE(vp, ENITags); err != nil {
		log.Fatalf("unable to parse %s: %s", ENITags, err)
	} else {
		c.ENITags = m
	}

	if m, err := command.GetStringMapStringE(vp, ENIGarbageCollectionTags); err != nil {
		log.Fatalf("unable to parse %s: %s", ENIGarbageCollectionTags, err)
	} else {
		c.ENIGarbageCollectionTags = m
	}

	if m, err := command.GetStringMapStringE(vp, IPAMMultiPoolMap); err != nil {
		log.Fatalf("unable to parse %s: %s", IPAMMultiPoolMap, err)
	} else {
		c.IPAMMultiPoolMap = m
	}
}

// Config represents the operator configuration.
var Config = &OperatorConfig{
	IPAMSubnetsIDs:           make([]string, 0),
	IPAMSubnetsTags:          make(map[string]string),
	IPAMInstanceTags:         make(map[string]string),
	IPAMMultiPoolMap:         make(map[string]string),
	AWSInstanceLimitMapping:  make(map[string]string),
	ENITags:                  make(map[string]string),
	ENIGarbageCollectionTags: make(map[string]string),
}
