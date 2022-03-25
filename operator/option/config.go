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

const (
	// EndpointGCIntervalDefault is the default time for the CEP GC
	EndpointGCIntervalDefault = 5 * time.Minute

	// PrometheusServeAddr is the default server address for operator metrics
	PrometheusServeAddr = ":6942"

	// CESMaxCEPsInCESDefault is the maximum number of cilium endpoints allowed in a CES
	CESMaxCEPsInCESDefault = 100

	// CESSlicingModeDefault is default method for grouping CEP in a CES.
	CESSlicingModeDefault = "cesSliceModeIdentity"
)

const (
	// BGPAnnounceLBIP announces service IPs of type LoadBalancer via BGP
	BGPAnnounceLBIP = "bgp-announce-lb-ip"

	// BGPConfigPath is the file path to the BGP configuration. It is
	// compatible with MetalLB's configuration.
	BGPConfigPath = "bgp-config-path"

	// SkipCRDCreation specifies whether the CustomResourceDefinition will be
	// disabled for the operator
	SkipCRDCreation = "skip-crd-creation"

	// CNPNodeStatusGCInterval is the GC interval for nodes which have been
	// removed from the cluster in CiliumNetworkPolicy and
	// CiliumClusterwideNetworkPolicy Status.
	CNPNodeStatusGCInterval = "cnp-node-status-gc-interval"

	// CNPStatusUpdateInterval is the interval between status updates
	// being sent to the K8s apiserver for a given CNP.
	CNPStatusUpdateInterval = "cnp-status-update-interval"

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

	// PProf enabled pprof debugging endpoint
	PProf = "pprof"

	// PProfPort is the port that the pprof listens on
	PProfPort = "pprof-port"

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

	// ParallelAllocWorkers specifies the number of parallel workers to be used for IPAM allocation
	ParallelAllocWorkers = "parallel-alloc-workers"

	// UpdateEC2AdapterLimitViaAPI configures the operator to use the EC2
	// API to fill out the instancetype to adapter limit mapping.
	UpdateEC2AdapterLimitViaAPI = "update-ec2-adapter-limit-via-api"

	// EC2APIEndpoint is the custom API endpoint to use for the EC2 AWS service,
	// e.g. "ec2-fips.us-west-1.amazonaws.com" to use a FIPS endpoint in the us-west-1 region.
	EC2APIEndpoint = "ec2-api-endpoint"

	// Azure options

	// AzureSubscriptionID is the subscription ID to use when accessing the Azure API
	AzureSubscriptionID = "azure-subscription-id"

	// AzureResourceGroup is the resource group of the nodes used for the cluster
	AzureResourceGroup = "azure-resource-group"

	// AzureUserAssignedIdentityID is the id of the user assigned identity used
	// for retrieving Azure API credentials
	AzureUserAssignedIdentityID = "azure-user-assigned-identity-id"

	// AzureUsePrimaryAddress specify wether we should use or ignore the interface's
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

	// EnableIngressController enables cilium ingress controller
	// This must be enabled along with enable-envoy-config in cilium agent.
	EnableIngressController = "enable-ingress-controller"

	// EnforceIngressHttps enforces https for host having matching TLS host in Ingress.
	// Incoming traffic to http listener will return 308 http error code with respective location in header.
	EnforceIngressHttps = "enforce-ingress-https"

	// CiliumK8sNamespace is the namespace where Cilium pods are running.
	CiliumK8sNamespace = "cilium-pod-namespace"

	// CiliumPodLabels specifies the pod labels that Cilium pods is running
	// with.
	CiliumPodLabels = "cilium-pod-labels"

	// RemoveCiliumNodeTaints is the flag to define if the Cilium node taint
	// should be removed in Kubernetes nodes.
	RemoveCiliumNodeTaints = "remove-cilium-node-taints"

	// SetCiliumIsUpCondition sets the CiliumIsUp node condition in Kubernetes
	// nodes.
	SetCiliumIsUpCondition = "set-cilium-is-up-condition"
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

	// EnableMetrics enables prometheus metrics.
	EnableMetrics bool

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

	OperatorAPIServeAddr        string
	OperatorPrometheusServeAddr string

	// PProf enables pprof debugging endpoint
	PProf bool

	// PProfPort is the port that the pprof listens on
	PProfPort int

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

	// BGPAnnounceLBIP announces service IPs of type LoadBalancer via BGP.
	BGPAnnounceLBIP bool

	// BGPConfigPath is the file path to the BGP configuration. It is
	// compatible with MetalLB's configuration.
	BGPConfigPath string

	// SkipCRDCreation disables creation of the CustomResourceDefinition
	// for the operator
	SkipCRDCreation bool

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

	// AWSEnablePrefixDelegation allows operator to allocate prefixes to ENIs on nitro instances instead of individual
	// IP addresses. Allows for increased pod density on nodes.
	AWSEnablePrefixDelegation bool

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

	// EnableIngressController enables cilium ingress controller
	EnableIngressController bool

	// EnforceIngressHTTPS enforces https if required
	EnforceIngressHTTPS bool

	// CiliumK8sNamespace is the namespace where Cilium pods are running.
	CiliumK8sNamespace string

	// CiliumPodLabels specifies the pod labels that Cilium pods is running
	// with.
	CiliumPodLabels string

	// RemoveCiliumNodeTaints is the flag to define if the Cilium node taint
	// should be removed in Kubernetes nodes.
	RemoveCiliumNodeTaints bool

	// SetCiliumIsUpCondition sets the CiliumIsUp node condition in Kubernetes
	// nodes.
	SetCiliumIsUpCondition bool
}

// Populate sets all options with the values from viper.
func (c *OperatorConfig) Populate() {
	c.CNPNodeStatusGCInterval = viper.GetDuration(CNPNodeStatusGCInterval)
	c.CNPStatusUpdateInterval = viper.GetDuration(CNPStatusUpdateInterval)
	c.EnableMetrics = viper.GetBool(EnableMetrics)
	c.EndpointGCInterval = viper.GetDuration(EndpointGCInterval)
	c.IdentityGCInterval = viper.GetDuration(IdentityGCInterval)
	c.IdentityGCRateInterval = viper.GetDuration(IdentityGCRateInterval)
	c.IdentityGCRateLimit = viper.GetInt64(IdentityGCRateLimit)
	c.IdentityHeartbeatTimeout = viper.GetDuration(IdentityHeartbeatTimeout)
	c.OperatorAPIServeAddr = viper.GetString(OperatorAPIServeAddr)
	c.OperatorPrometheusServeAddr = viper.GetString(OperatorPrometheusServeAddr)
	c.PProf = viper.GetBool(PProf)
	c.PProfPort = viper.GetInt(PProfPort)
	c.SyncK8sServices = viper.GetBool(SyncK8sServices)
	c.SyncK8sNodes = viper.GetBool(SyncK8sNodes)
	c.UnmanagedPodWatcherInterval = viper.GetInt(UnmanagedPodWatcherInterval)
	c.NodeCIDRMaskSizeIPv4 = viper.GetInt(NodeCIDRMaskSizeIPv4)
	c.NodeCIDRMaskSizeIPv6 = viper.GetInt(NodeCIDRMaskSizeIPv6)
	c.ClusterPoolIPv4CIDR = viper.GetStringSlice(ClusterPoolIPv4CIDR)
	c.ClusterPoolIPv6CIDR = viper.GetStringSlice(ClusterPoolIPv6CIDR)
	c.LeaderElectionLeaseDuration = viper.GetDuration(LeaderElectionLeaseDuration)
	c.LeaderElectionRenewDeadline = viper.GetDuration(LeaderElectionRenewDeadline)
	c.LeaderElectionRetryPeriod = viper.GetDuration(LeaderElectionRetryPeriod)
	c.BGPAnnounceLBIP = viper.GetBool(BGPAnnounceLBIP)
	c.BGPConfigPath = viper.GetString(BGPConfigPath)
	c.SkipCRDCreation = viper.GetBool(SkipCRDCreation)
	c.EnableIngressController = viper.GetBool(EnableIngressController)
	c.EnforceIngressHTTPS = viper.GetBool(EnforceIngressHttps)
	c.CiliumPodLabels = viper.GetString(CiliumPodLabels)
	c.RemoveCiliumNodeTaints = viper.GetBool(RemoveCiliumNodeTaints)
	c.SetCiliumIsUpCondition = viper.GetBool(SetCiliumIsUpCondition)

	c.CiliumK8sNamespace = viper.GetString(CiliumK8sNamespace)
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

	// AWS options

	c.AWSReleaseExcessIPs = viper.GetBool(AWSReleaseExcessIPs)
	c.AWSEnablePrefixDelegation = viper.GetBool(AWSEnablePrefixDelegation)
	c.UpdateEC2AdapterLimitViaAPI = viper.GetBool(UpdateEC2AdapterLimitViaAPI)
	c.EC2APIEndpoint = viper.GetString(EC2APIEndpoint)
	c.ExcessIPReleaseDelay = viper.GetInt(ExcessIPReleaseDelay)

	// Azure options

	c.AzureSubscriptionID = viper.GetString(AzureSubscriptionID)
	c.AzureResourceGroup = viper.GetString(AzureResourceGroup)
	c.AzureUsePrimaryAddress = viper.GetBool(AzureUsePrimaryAddress)
	c.AzureUserAssignedIdentityID = viper.GetString(AzureUserAssignedIdentityID)

	// AlibabaCloud options

	c.AlibabaCloudVPCID = viper.GetString(AlibabaCloudVPCID)
	c.AlibabaCloudReleaseExcessIPs = viper.GetBool(AlibabaCloudReleaseExcessIPs)

	// CiliumEndpointSlice options
	c.CESMaxCEPsInCES = viper.GetInt(CESMaxCEPsInCES)
	c.CESSlicingMode = viper.GetString(CESSlicingMode)

	// Option maps and slices

	if m := viper.GetStringSlice(IPAMSubnetsIDs); len(m) != 0 {
		c.IPAMSubnetsIDs = m
	}

	if m, err := command.GetStringMapStringE(viper.GetViper(), IPAMSubnetsTags); err != nil {
		log.Fatalf("unable to parse %s: %s", IPAMSubnetsTags, err)
	} else {
		c.IPAMSubnetsTags = m
	}

	if m, err := command.GetStringMapStringE(viper.GetViper(), IPAMInstanceTags); err != nil {
		log.Fatalf("unable to parse %s: %s", IPAMInstanceTags, err)
	} else {
		c.IPAMInstanceTags = m
	}

	if m, err := command.GetStringMapStringE(viper.GetViper(), AWSInstanceLimitMapping); err != nil {
		log.Fatalf("unable to parse %s: %s", AWSInstanceLimitMapping, err)
	} else {
		c.AWSInstanceLimitMapping = m
	}

	if m, err := command.GetStringMapStringE(viper.GetViper(), ENITags); err != nil {
		log.Fatalf("unable to parse %s: %s", ENITags, err)
	} else {
		c.ENITags = m
	}
}

// Config represents the operator configuration.
var Config = &OperatorConfig{
	IPAMSubnetsIDs:          make([]string, 0),
	IPAMSubnetsTags:         make(map[string]string),
	IPAMInstanceTags:        make(map[string]string),
	AWSInstanceLimitMapping: make(map[string]string),
	ENITags:                 make(map[string]string),
}
