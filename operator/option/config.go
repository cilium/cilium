// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/spf13/viper"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/option"
)

const (
	// EndpointGCIntervalDefault is the default time for the CEP GC
	EndpointGCIntervalDefault = 5 * time.Minute

	// PprofAddressOperator is the default value for pprof in the operator
	PprofAddressOperator = "localhost"

	// PprofPortOperator is the default value for pprof in the operator
	PprofPortOperator = 6061

	// DefaultProxyIdleTimeoutSeconds is the default value for the proxy idle timeout
	DefaultProxyIdleTimeoutSeconds = 60

	// DefaultProxyStreamIdleTimeoutSeconds is the default value for the proxy stream idle timeout
	DefaultProxyStreamIdleTimeoutSeconds = 300
)

const (
	// EnableMetrics enables prometheus metrics.
	EnableMetrics = "enable-metrics"

	// EndpointGCInterval is the interval between attempts of the CEP GC
	// controller.
	// Note that only one node per cluster should run this, and most iterations
	// will simply return.
	EndpointGCInterval = "cilium-endpoint-gc-interval"

	// NodesGCInterval is the duration for which the cilium nodes are GC.
	NodesGCInterval = "nodes-gc-interval"

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

	// IPAMInstanceTags are optional tags used to filter instances for ENI discovery.
	// Only used with AWS and Alibabacloud IPAM mode for now
	IPAMInstanceTags = "instance-tags-filter"

	// IPAMAutoCreateCiliumPodIPPools contains pre-defined IP pools to be auto-created on startup.
	IPAMAutoCreateCiliumPodIPPools = "auto-create-cilium-pod-ip-pools"

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

	// ProxyIdleTimeoutSeconds is the idle timeout for proxy connections to upstream clusters
	ProxyIdleTimeoutSeconds = "proxy-idle-timeout-seconds"

	// ProxyStreamIdleTimeoutSeconds is the stream timeout for proxy connections to upstream clusters
	ProxyStreamIdleTimeoutSeconds = "proxy-stream-idle-timeout-seconds"

	// EnableGatewayAPI enables support of Gateway API
	// This must be enabled along with enable-envoy-config in cilium agent.
	EnableGatewayAPI = "enable-gateway-api"

	// KubeProxyReplacement is equivalent to the cilium-agent option, and
	// is used to provide hints for misconfiguration.
	KubeProxyReplacement = "kube-proxy-replacement"

	// EnableNodePort is equivalent to the cilium-agent option, and
	// is used to provide hints for misconfiguration.
	EnableNodePort = "enable-node-port"

	// CiliumK8sNamespace is the namespace where Cilium pods are running.
	CiliumK8sNamespace = "cilium-pod-namespace"

	// CiliumPodLabels specifies the pod labels that Cilium pods is running
	// with.
	CiliumPodLabels = "cilium-pod-labels"

	// TaintSyncWorkers is the number of workers used to synchronize
	// taints and conditions in Kubernetes nodes.
	TaintSyncWorkers = "taint-sync-workers"

	// RemoveCiliumNodeTaints is the flag to define if the Cilium node taint
	// should be removed in Kubernetes nodes.
	RemoveCiliumNodeTaints = "remove-cilium-node-taints"

	// SetCiliumNodeTaints is whether or not to taint nodes that do not have
	// a running Cilium instance.
	SetCiliumNodeTaints = "set-cilium-node-taints"

	// SetCiliumIsUpCondition sets the CiliumIsUp node condition in Kubernetes
	// nodes.
	SetCiliumIsUpCondition = "set-cilium-is-up-condition"

	// PodRestartSelector specify the labels contained in the pod that needs to be restarted before the node can be de-stained
	// default values: k8s-app=kube-dns
	PodRestartSelector = "pod-restart-selector"
)

// OperatorConfig is the configuration used by the operator.
type OperatorConfig struct {
	// NodesGCInterval is the GC interval for CiliumNodes
	NodesGCInterval time.Duration

	// EnableMetrics enables prometheus metrics.
	EnableMetrics bool

	// EndpointGCInterval is the interval between attempts of the CEP GC
	// controller.
	// Note that only one node per cluster should run this, and most iterations
	// will simply return.
	EndpointGCInterval time.Duration

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

	// IPAM options

	// IPAMAPIBurst is the burst value allowed when accessing external IPAM APIs
	IPAMAPIBurst int

	// IPAMAPIQPSLimit is the queries per second limit when accessing external IPAM APIs
	IPAMAPIQPSLimit float64

	// IPAMSubnetsIDs are optional subnets IDs used to filter subnets and interfaces listing
	IPAMSubnetsIDs []string

	// IPAMSubnetsTags are optional tags used to filter subnets, and interfaces within those subnets
	IPAMSubnetsTags map[string]string

	// IPAMInstanceTags are optional tags used to filter instances for ENI discovery.
	// Only used with AWS and Alibabacloud IPAM mode for now
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

	// IPAMAutoCreateCiliumPodIPPools contains pre-defined IP pools to be auto-created on startup.
	IPAMAutoCreateCiliumPodIPPools map[string]string

	// KubeProxyReplacement or NodePort are required to implement cluster
	// Ingress (or equivalent Gateway API functionality)
	KubeProxyReplacement string
	EnableNodePort       bool

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

	// EnableGatewayAPI enables support of Gateway API
	EnableGatewayAPI bool

	// ProxyIdleTimeoutSeconds is the idle timeout for the proxy to upstream cluster
	ProxyIdleTimeoutSeconds int

	// ProxyStreamIdleTimeoutSeconds is the stream idle timeout for the proxy to upstream cluster
	ProxyStreamIdleTimeoutSeconds int

	// CiliumK8sNamespace is the namespace where Cilium pods are running.
	CiliumK8sNamespace string

	// CiliumPodLabels specifies the pod labels that Cilium pods is running
	// with.
	CiliumPodLabels string

	// TaintSyncWorkers is the number of workers used to synchronize
	// taints and conditions in Kubernetes nodes.
	TaintSyncWorkers int

	// RemoveCiliumNodeTaints is the flag to define if the Cilium node taint
	// should be removed in Kubernetes nodes.
	RemoveCiliumNodeTaints bool

	// SetCiliumNodeTaints is whether or not to set taints on nodes that do not
	// have a running Cilium pod.
	SetCiliumNodeTaints bool

	// SetCiliumIsUpCondition sets the CiliumIsUp node condition in Kubernetes
	// nodes.
	SetCiliumIsUpCondition bool

	// PodRestartSelector specify the labels contained in the pod that needs to be restarted before the node can be de-stained
	PodRestartSelector string
}

// Populate sets all options with the values from viper.
func (c *OperatorConfig) Populate(logger *slog.Logger, vp *viper.Viper) {
	c.NodesGCInterval = vp.GetDuration(NodesGCInterval)
	c.EnableMetrics = vp.GetBool(EnableMetrics)
	c.EndpointGCInterval = vp.GetDuration(EndpointGCInterval)
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
	c.EnableGatewayAPI = vp.GetBool(EnableGatewayAPI)
	c.ProxyIdleTimeoutSeconds = vp.GetInt(ProxyIdleTimeoutSeconds)
	if c.ProxyIdleTimeoutSeconds == 0 {
		c.ProxyIdleTimeoutSeconds = DefaultProxyIdleTimeoutSeconds
	}
	c.ProxyStreamIdleTimeoutSeconds = vp.GetInt(ProxyStreamIdleTimeoutSeconds)
	if c.ProxyStreamIdleTimeoutSeconds == 0 {
		c.ProxyStreamIdleTimeoutSeconds = DefaultProxyStreamIdleTimeoutSeconds
	}
	c.CiliumPodLabels = vp.GetString(CiliumPodLabels)
	c.TaintSyncWorkers = vp.GetInt(TaintSyncWorkers)
	c.RemoveCiliumNodeTaints = vp.GetBool(RemoveCiliumNodeTaints)
	c.SetCiliumNodeTaints = vp.GetBool(SetCiliumNodeTaints)
	c.SetCiliumIsUpCondition = vp.GetBool(SetCiliumIsUpCondition)
	c.PodRestartSelector = vp.GetString(PodRestartSelector)

	c.CiliumK8sNamespace = vp.GetString(CiliumK8sNamespace)

	if c.CiliumK8sNamespace == "" {
		if option.Config.K8sNamespace == "" {
			c.CiliumK8sNamespace = metav1.NamespaceDefault
		} else {
			c.CiliumK8sNamespace = option.Config.K8sNamespace
		}
	}

	// IPAM options

	c.IPAMAPIQPSLimit = vp.GetFloat64(IPAMAPIQPSLimit)
	c.IPAMAPIBurst = vp.GetInt(IPAMAPIBurst)
	c.ParallelAllocWorkers = vp.GetInt64(ParallelAllocWorkers)

	// Gateways and Ingress
	c.KubeProxyReplacement = vp.GetString(KubeProxyReplacement)
	c.EnableNodePort = vp.GetBool(EnableNodePort)

	// AWS options

	c.AWSReleaseExcessIPs = vp.GetBool(AWSReleaseExcessIPs)
	c.AWSEnablePrefixDelegation = vp.GetBool(AWSEnablePrefixDelegation)
	c.AWSUsePrimaryAddress = vp.GetBool(AWSUsePrimaryAddress)
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

	// Option maps and slices

	if m := vp.GetStringSlice(IPAMSubnetsIDs); len(m) != 0 {
		c.IPAMSubnetsIDs = m
	}

	if m, err := command.GetStringMapStringE(vp, IPAMSubnetsTags); err != nil {
		logging.Fatal(logger, fmt.Sprintf("unable to parse %s: %s", IPAMSubnetsTags, err))
	} else {
		c.IPAMSubnetsTags = m
	}

	if m, err := command.GetStringMapStringE(vp, IPAMInstanceTags); err != nil {
		logging.Fatal(logger, fmt.Sprintf("unable to parse %s: %s", IPAMInstanceTags, err))
	} else {
		c.IPAMInstanceTags = m
	}

	if m, err := command.GetStringMapStringE(vp, ENITags); err != nil {
		logging.Fatal(logger, fmt.Sprintf("unable to parse %s: %s", ENITags, err))
	} else {
		c.ENITags = m
	}

	if m, err := command.GetStringMapStringE(vp, ENIGarbageCollectionTags); err != nil {
		logging.Fatal(logger, fmt.Sprintf("unable to parse %s: %s", ENIGarbageCollectionTags, err))
	} else {
		c.ENIGarbageCollectionTags = m
	}

	if m, err := command.GetStringMapStringE(vp, IPAMAutoCreateCiliumPodIPPools); err != nil {
		logging.Fatal(logger, fmt.Sprintf("unable to parse %s: %s", IPAMAutoCreateCiliumPodIPPools, err))
	} else {
		c.IPAMAutoCreateCiliumPodIPPools = m
	}
}

// Config represents the operator configuration.
var Config = &OperatorConfig{
	IPAMSubnetsIDs:                 make([]string, 0),
	IPAMSubnetsTags:                make(map[string]string),
	IPAMInstanceTags:               make(map[string]string),
	IPAMAutoCreateCiliumPodIPPools: make(map[string]string),
	ENITags:                        make(map[string]string),
	ENIGarbageCollectionTags:       make(map[string]string),
}
