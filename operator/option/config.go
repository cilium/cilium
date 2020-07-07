// Copyright 2020 Authors of Cilium
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

package option

import (
	"time"

	"github.com/spf13/viper"
)

const (
	// EndpointGCIntervalDefault is the default time for the CEP GC
	EndpointGCIntervalDefault = 5 * time.Minute
)

const (
	// CNPNodeStatusGCInterval is the GC interval for nodes which have been
	// removed from the cluster in CiliumNetworkPolicy and
	// CiliumClusterwideNetworkPolicy Status.
	CNPNodeStatusGCInterval = "cnp-node-status-gc-interval"

	// CNPStatusUpdateInterval is the interval between status updates
	// being sent to the K8s apiserver for a given CNP.
	CNPStatusUpdateInterval = "cnp-status-update-interval"

	// EnableCEPGC enables CiliumEndpoint garbage collector
	// Deprecated: use EndpointGCInterval and remove in 1.9
	EnableCEPGC = "cilium-endpoint-gc"

	// EnableCCNPNodeStatusGC enables CiliumClusterwideNetworkPolicy Status
	// garbage collection for nodes which have been removed from the cluster
	// Deprecated: use CNPNodeStatusGCInterval and remove in 1.9
	EnableCCNPNodeStatusGC = "ccnp-node-status-gc"

	// EnableCNPNodeStatusGC enables CiliumNetworkPolicy Status garbage
	// collection for nodes which have been removed from the cluster
	// Deprecated: use CNPNodeStatusGCInterval and remove in 1.9
	EnableCNPNodeStatusGC = "cnp-node-status-gc"

	// EnableMetrics enables prometheus metrics.
	EnableMetrics = "enable-metrics"

	// EndpointGCInterval is the interval between attempts of the CEP GC
	// controller.
	// Note that only one node per cluster should run this, and most iterations
	// will simply return.
	EndpointGCInterval = "cilium-endpoint-gc-interval"

	// IdentityGCInterval is the interval in which allocator identities are
	// attempted to be expired from the kvstore
	IdentityGCInterval = "identity-gc-interval"

	// IdentityGCRateInterval is the interval used for rate limiting the GC of
	// identities.
	IdentityGCRateInterval = "identity-gc-rate-interval"

	// IdentityGCRateLimit is the maximum identities used for rate limiting the
	// GC of identities.
	IdentityGCRateLimit = "identity-gc-rate-limit"

	// IdentityHeartbeatTimeout is the timeout used to GC identities from k8s
	IdentityHeartbeatTimeout = "identity-heartbeat-timeout"

	// NodesGCInterval is the duration for which the nodes are GC in the KVStore.
	NodesGCInterval = "nodes-gc-interval"

	// OperatorAPIServeAddr IP:Port on which to serve api requests in
	// operator (pass ":Port" to bind on all interfaces, "" is off)
	OperatorAPIServeAddr = "operator-api-serve-addr"

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

	// AWSClientBurstDeprecated is the deprecated version of IPAMAPIBurst and will be rewmoved in v1.9
	AWSClientBurstDeprecated = "aws-client-burst"

	// AWSClientQPSLimitDeprecated is the deprecated version of IPAMAPIQPSLimit and will be removed in v1.9
	AWSClientQPSLimitDeprecated = "aws-client-qps"

	// IPAMAPIBurst is the burst value allowed when accessing external IPAM APIs
	IPAMAPIBurst = "limit-ipam-api-burst"

	// IPAMAPIQPSLimit is the queries per second limit when accessing external IPAM APIs
	IPAMAPIQPSLimit = "limit-ipam-api-qps"

	// IPAMSubnetsIDs are optional subnets IDs used to filter subnets and interfaces listing
	IPAMSubnetsIDs = "subnet-ids-filter"

	// IAPMSubnetsTags are optional tags used to filter subnets, and interfaces within those subnets
	IPAMSubnetsTags = "subnet-tags-filter"

	// IPAMOperatorV4CIDR is the cluster IPv4 podCIDR that should be used to
	// allocate pods in the node.
	IPAMOperatorV4CIDR = "cluster-pool-ipv4-cidr"

	// IPAMOperatorV6CIDR is the cluster IPv6 podCIDR that should be used to
	// allocate pods in the node.
	IPAMOperatorV6CIDR = "cluster-pool-ipv6-cidr"

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

	// ENITags are the tags that will be added to every ENI created by the
	// AWS ENI IPAM.
	ENITags = "eni-tags"

	// ENIParallelWorkersDeprecated is the deprecated name of the option
	// ParallelAllocWorkers that can be removed in Cilium 1.9
	ENIParallelWorkersDeprecated = "eni-parallel-workers"

	// ParallelAllocWorkers specifies the number of parallel workers to be used for IPAM allocation
	ParallelAllocWorkers = "parallel-alloc-workers"

	// UpdateEC2AdapterLimitViaAPI configures the operator to use the EC2
	// API to fill out the instnacetype to adapter limit mapping.
	UpdateEC2AdapterLimitViaAPI = "update-ec2-apdater-limit-via-api"

	// Azure options

	// AzureSubscriptionID is the subscription ID to use when accessing the Azure API
	AzureSubscriptionID = "azure-subscription-id"

	// AzureResourceGroup is the resource group of the nodes used for the cluster
	AzureResourceGroup = "azure-resource-group"

	// CRDWaitTimeout it the time after which Cilium CRDs have to be available.
	CRDWaitTimeout = "crd-wait-timeout"
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

	// EnableCEPGC enables CiliumEndpoint garbage collector
	// Deprecated: use EndpointGCInterval and remove in 1.9
	EnableCEPGC bool

	// EnableCNPNodeStatusGC enables CiliumNetworkPolicy Status garbage collection
	// for nodes which have been removed from the cluster
	// Deprecated: use CNPNodeStatusGCInterval and remove in 1.9
	EnableCNPNodeStatusGC bool

	// EnableMetrics enables prometheus metrics.
	EnableMetrics bool

	// EnableCCNPNodeStatusGC enables CiliumClusterwideNetworkPolicy Status
	// garbage collection for nodes which have been removed from the cluster
	// Deprecated: use CNPNodeStatusGCInterval and remove in 1.9
	EnableCCNPNodeStatusGC bool

	// EndpointGCInterval is the interval between attempts of the CEP GC
	// controller.
	// Note that only one node per cluster should run this, and most iterations
	// will simply return.
	EndpointGCInterval time.Duration

	// IdentityGCInterval is the interval in which allocator identities are
	// attempted to be expired from the kvstore
	IdentityGCInterval time.Duration

	// IdentityGCRateInterval is the interval used for rate limiting the GC of
	// identities.
	IdentityGCRateInterval time.Duration

	// IdentityGCRateLimit is the maximum identities used for rate limiting the
	// GC of identities.
	IdentityGCRateLimit int64

	// IdentityHeartbeatTimeout is the timeout used to GC identities from k8s
	IdentityHeartbeatTimeout time.Duration

	// NodesGCInterval is the duration for which the nodes are GC in the KVStore.
	NodesGCInterval time.Duration

	OperatorAPIServeAddr        string
	OperatorPrometheusServeAddr string

	// SyncK8sServices synchronizes k8s services into the kvstore
	SyncK8sServices bool

	// SyncK8sNodes synchronizes k8s nodes into the kvstore
	SyncK8sNodes bool

	// UnmanagedPodWatcherInterval is the interval to check for unmanaged kube-dns pods (0 to disable)
	UnmanagedPodWatcherInterval int

	// IPAM options

	// IPAMAPIBurst is the burst value allowed when accessing external IPAM APIs
	IPAMAPIBurst int

	// IPAMAPIQPSLimit is the queries per second limit when accessing external IPAM APIs
	IPAMAPIQPSLimit float64

	// IPAMSubnetsIDs are optional subnets IDs used to filter subnets and interfaces listing
	IPAMSubnetsIDs []string

	// IPAMSubnetsTags are optional tags used to filter subnets, and interfaces within those subnets
	IPAMSubnetsTags map[string]string

	// IPAM Operator options

	// IPAMOperatorV4CIDR is the cluster IPv4 podCIDR that should be used to
	// allocate pods in the node.
	IPAMOperatorV4CIDR []string

	// IPAMOperatorV6CIDR is the cluster IPv6 podCIDR that should be used to
	// allocate pods in the node.
	IPAMOperatorV6CIDR []string

	// NodeCIDRMaskSizeIPv4 is the IPv4 podCIDR mask size that will be used
	// per node.
	NodeCIDRMaskSizeIPv4 int

	// NodeCIDRMaskSizeIPv6 is the IPv6 podCIDR mask size that will be used
	// per node.
	NodeCIDRMaskSizeIPv6 int

	// AWS options

	// ENITags are the tags that will be added to every ENI created by the AWS ENI IPAM
	ENITags map[string]string

	// ParallelAllocWorkers specifies the number of parallel workers to be used in ENI mode.
	ParallelAllocWorkers int64

	// AWSInstanceLimitMapping allows overwriting AWS instance limits defined in
	// pkg/aws/eni/limits.go
	// e.g. {"a1.medium": "2,4,4", "a2.custom2": "4,5,6"}
	AWSInstanceLimitMapping map[string]string

	// AWSReleaseExcessIps allows releasing excess free IP addresses from ENI.
	// Enabling this option reduces waste of IP addresses but may increase
	// the number of API calls to AWS EC2 service.
	AWSReleaseExcessIPs bool

	// UpdateEC2AdapterLimitViaAPI configures the operator to use the EC2 API to fill out the instnacetype to adapter limit mapping
	UpdateEC2AdapterLimitViaAPI bool

	// Azure options

	// AzureSubscriptionID is the subscription ID to use when accessing the Azure API
	AzureSubscriptionID string

	// AzureResourceGroup is the resource group of the nodes used for the cluster
	AzureResourceGroup string

	// CRDWaitTimeout it the time after which Cilium CRDs have to be available.
	CRDWaitTimeout time.Duration
}

func (c *OperatorConfig) Populate() {
	c.CNPNodeStatusGCInterval = viper.GetDuration(CNPNodeStatusGCInterval)
	c.CNPStatusUpdateInterval = viper.GetDuration(CNPStatusUpdateInterval)
	c.EnableCEPGC = viper.GetBool(EnableCEPGC)
	c.EnableCNPNodeStatusGC = viper.GetBool(EnableCNPNodeStatusGC)
	c.EnableCCNPNodeStatusGC = viper.GetBool(EnableCCNPNodeStatusGC)
	c.EnableMetrics = viper.GetBool(EnableMetrics)
	c.EndpointGCInterval = viper.GetDuration(EndpointGCInterval)
	c.IdentityGCInterval = viper.GetDuration(IdentityGCInterval)
	c.IdentityGCRateInterval = viper.GetDuration(IdentityGCRateInterval)
	c.IdentityGCRateLimit = viper.GetInt64(IdentityGCRateLimit)
	c.IdentityHeartbeatTimeout = viper.GetDuration(IdentityHeartbeatTimeout)
	c.NodesGCInterval = viper.GetDuration(NodesGCInterval)
	c.OperatorAPIServeAddr = viper.GetString(OperatorAPIServeAddr)
	c.OperatorPrometheusServeAddr = viper.GetString(OperatorPrometheusServeAddr)
	c.SyncK8sServices = viper.GetBool(SyncK8sServices)
	c.SyncK8sNodes = viper.GetBool(SyncK8sNodes)
	c.UnmanagedPodWatcherInterval = viper.GetInt(UnmanagedPodWatcherInterval)
	c.NodeCIDRMaskSizeIPv4 = viper.GetInt(NodeCIDRMaskSizeIPv4)
	c.NodeCIDRMaskSizeIPv6 = viper.GetInt(NodeCIDRMaskSizeIPv6)
	c.IPAMOperatorV4CIDR = viper.GetStringSlice(IPAMOperatorV4CIDR)
	c.IPAMOperatorV6CIDR = viper.GetStringSlice(IPAMOperatorV6CIDR)
	c.NodesGCInterval = viper.GetDuration(NodesGCInterval)
	c.CRDWaitTimeout = viper.GetDuration(CRDWaitTimeout)

	// AWS options

	c.AWSReleaseExcessIPs = viper.GetBool(AWSReleaseExcessIPs)
	c.UpdateEC2AdapterLimitViaAPI = viper.GetBool(UpdateEC2AdapterLimitViaAPI)

	// Azure options

	c.AzureSubscriptionID = viper.GetString(AzureSubscriptionID)
	c.AzureResourceGroup = viper.GetString(AzureResourceGroup)

	// Deprecated options

	if val := viper.GetInt(AWSClientBurstDeprecated); val != 0 {
		c.IPAMAPIBurst = val
	} else {
		c.IPAMAPIBurst = viper.GetInt(IPAMAPIBurst)
	}

	if val := viper.GetFloat64(AWSClientQPSLimitDeprecated); val != 0 {
		c.IPAMAPIQPSLimit = val
	} else {
		c.IPAMAPIQPSLimit = viper.GetFloat64(IPAMAPIQPSLimit)
	}

	if val := viper.GetInt64(ENIParallelWorkersDeprecated); val != 0 {
		c.ParallelAllocWorkers = val
	} else {
		c.ParallelAllocWorkers = viper.GetInt64(ParallelAllocWorkers)
	}

	// Option maps and slices

	if m := viper.GetStringSlice(IPAMSubnetsIDs); len(m) != 0 {
		c.IPAMSubnetsIDs = m
	}

	if m := viper.GetStringMapString(IPAMSubnetsTags); len(m) != 0 {
		c.IPAMSubnetsTags = m
	}

	if m := viper.GetStringMapString(AWSInstanceLimitMapping); len(m) != 0 {
		c.AWSInstanceLimitMapping = m
	}

	if m := viper.GetStringMapString(ENITags); len(m) != 0 {
		c.ENITags = m
	}
}

// Config represents the operator configuration.
var Config = &OperatorConfig{
	IPAMSubnetsIDs:          make([]string, 0),
	IPAMSubnetsTags:         make(map[string]string),
	AWSInstanceLimitMapping: make(map[string]string),
	ENITags:                 make(map[string]string),
}
