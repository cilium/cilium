// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

// Cell implements the CID Controller. It subscribes to CID, CES, Pods
// and Namespace events and reconciles the state of CID in the cluster.
var Cell = cell.Module(
	"k8s-cid-controller",
	"Cilium Identity Controller Operator",
	cell.Invoke(registerController),
	metrics.Metric(NewMetrics),
	cell.Config(defaultConfig),
)

type config struct {
	IdentityManagementMode string `mapstructure:"identity-management-mode"`
}

func (c config) Flags(flags *pflag.FlagSet) {
	flags.String(option.IdentityManagementMode, c.IdentityManagementMode, "Configure whether Cilium Identities are managed by cilium-agent, cilium-operator, or both")
}

var defaultConfig = config{
	IdentityManagementMode: option.IdentityManagementModeAgent,
}

// SharedConfig contains the configuration that is shared between
// this module and others.
// It is a temporary solution meant to avoid polluting this module with a direct
// dependency on global operator and daemon configurations.
type SharedConfig struct {
	// EnableCiliumEndpointSlice indicates if the Cilium Endpoint Slice feature is
	// enabled.
	EnableCiliumEndpointSlice bool
	// DisableNetworkPolicy indicates if the network policy enforcement system is
	// disabled for K8s, Cilium and Cilium Clusterwide network policies.
	DisableNetworkPolicy bool
}
