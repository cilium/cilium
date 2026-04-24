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
	// SyncK8sServices synchronizes k8s services into the kvstore
	SyncK8sServices = "synchronize-k8s-services"

	// IPAM options

	// IPAMInstanceTags are optional tags used to filter instances for ENI discovery.
	// Only used with AWS and Alibabacloud IPAM mode for now
	IPAMInstanceTags = "instance-tags-filter"

	// ParallelAllocWorkers specifies the number of parallel workers to be used for IPAM allocation
	ParallelAllocWorkers = "parallel-alloc-workers"

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

	// LeaderElectionResourceLockTimeout is the timeout for the HTTP requests to acquire/renew
	// the leader election resource lock. When set to 0, defaults to max(1s, RenewDeadline/2).
	LeaderElectionResourceLockTimeout = "leader-election-resource-lock-timeout"

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

	// CiliumK8sNamespace is the namespace where Cilium pods are running.
	CiliumK8sNamespace = "cilium-pod-namespace"

	// CiliumPodLabels specifies the pod labels that Cilium pods is running
	// with.
	CiliumPodLabels = "cilium-pod-labels"
)

// OperatorConfig is the configuration used by the operator.
type OperatorConfig struct {
	// SyncK8sServices synchronizes k8s services into the kvstore
	SyncK8sServices bool

	// LeaderElectionLeaseDuration is the duration that non-leader candidates will wait to
	// force acquire leadership in Cilium Operator HA deployment.
	LeaderElectionLeaseDuration time.Duration

	// LeaderElectionRenewDeadline is the duration that the current acting master in HA deployment
	// will retry refreshing leadership in before giving up the lock.
	LeaderElectionRenewDeadline time.Duration

	// LeaderElectionRetryPeriod is the duration that LeaderElector clients should wait between
	// retries of the actions in operator HA deployment.
	LeaderElectionRetryPeriod time.Duration

	// LeaderElectionResourceLockTimeout is the timeout for the HTTP requests to acquire/renew
	// the leader election resource lock. When set to 0, defaults to max(1s, RenewDeadline/2).
	LeaderElectionResourceLockTimeout time.Duration

	// IPAM options

	// IPAMInstanceTags are optional tags used to filter instances for ENI discovery.
	// Only used with AWS and Alibabacloud IPAM mode for now
	IPAMInstanceTags map[string]string

	// KubeProxyReplacement is required to implement cluster
	// Ingress (or equivalent Gateway API functionality)
	KubeProxyReplacement bool

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
}

// Populate sets all options with the values from viper.
func (c *OperatorConfig) Populate(logger *slog.Logger, vp *viper.Viper) {
	c.SyncK8sServices = vp.GetBool(SyncK8sServices)
	c.LeaderElectionLeaseDuration = vp.GetDuration(LeaderElectionLeaseDuration)
	c.LeaderElectionRenewDeadline = vp.GetDuration(LeaderElectionRenewDeadline)
	c.LeaderElectionRetryPeriod = vp.GetDuration(LeaderElectionRetryPeriod)
	c.LeaderElectionResourceLockTimeout = vp.GetDuration(LeaderElectionResourceLockTimeout)
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

	c.CiliumK8sNamespace = vp.GetString(CiliumK8sNamespace)

	if c.CiliumK8sNamespace == "" {
		if option.Config.K8sNamespace == "" {
			c.CiliumK8sNamespace = metav1.NamespaceDefault
		} else {
			c.CiliumK8sNamespace = option.Config.K8sNamespace
		}
	}

	// Gateways and Ingress
	c.KubeProxyReplacement = vp.GetBool(KubeProxyReplacement)

	// Option maps and slices

	if m, err := command.GetStringMapStringE(vp, IPAMInstanceTags); err != nil {
		logging.Fatal(logger, fmt.Sprintf("unable to parse %s: %s", IPAMInstanceTags, err))
	} else {
		c.IPAMInstanceTags = m
	}
}

// Config represents the operator configuration.
var Config = &OperatorConfig{
	IPAMInstanceTags: make(map[string]string),
}
