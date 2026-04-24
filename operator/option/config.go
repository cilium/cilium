// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"fmt"
	"log/slog"

	"github.com/spf13/viper"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/logging"
)

const (
	// PprofAddressOperator is the default value for pprof in the operator
	PprofAddressOperator = "localhost"

	// PprofPortOperator is the default value for pprof in the operator
	PprofPortOperator = 6061
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

	// AlibabaCloud options

	// AlibabaCloudVPCID allows user to specific vpc
	AlibabaCloudVPCID = "alibaba-cloud-vpc-id"

	// AlibabaCloudReleaseExcessIPs allows releasing excess free IP addresses from ENI.
	// Enabling this option reduces waste of IP addresses but may increase
	// the number of API calls to AlibabaCloud ECS service.
	AlibabaCloudReleaseExcessIPs = "alibaba-cloud-release-excess-ips"

	// EnableGatewayAPI enables support of Gateway API
	// This must be enabled along with enable-envoy-config in cilium agent.
	EnableGatewayAPI = "enable-gateway-api"

	// KubeProxyReplacement is equivalent to the cilium-agent option, and
	// is used to provide hints for misconfiguration.
	KubeProxyReplacement = "kube-proxy-replacement"
)

// OperatorConfig is the configuration used by the operator.
type OperatorConfig struct {
	// SyncK8sServices synchronizes k8s services into the kvstore
	SyncK8sServices bool

	// IPAM options

	// IPAMInstanceTags are optional tags used to filter instances for ENI discovery.
	// Only used with AWS and Alibabacloud IPAM mode for now
	IPAMInstanceTags map[string]string

	// KubeProxyReplacement is required to implement cluster
	// Ingress (or equivalent Gateway API functionality)
	KubeProxyReplacement bool

	// EnableGatewayAPI enables support of Gateway API
	EnableGatewayAPI bool
}

// Populate sets all options with the values from viper.
func (c *OperatorConfig) Populate(logger *slog.Logger, vp *viper.Viper) {
	c.SyncK8sServices = vp.GetBool(SyncK8sServices)
	c.EnableGatewayAPI = vp.GetBool(EnableGatewayAPI)

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
