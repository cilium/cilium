// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/metrics"
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
	EnableOperatorManageCIDs bool `mapstructure:"operator-manages-identities"`
}

func (c config) Flags(flags *pflag.FlagSet) {
	flags.Bool("operator-manages-identities", c.EnableOperatorManageCIDs, "Enables operator to manage Cilium Identities by running a Cilium Identity controller")
	flags.MarkHidden("operator-manages-identities") // See https://github.com/cilium/cilium/issues/34675
}

var defaultConfig = config{
	EnableOperatorManageCIDs: false,
}

// SharedConfig contains the configuration that is shared between
// this module and others.
// It is a temporary solution meant to avoid polluting this module with a direct
// dependency on global operator and daemon configurations.
type SharedConfig struct {
	// EnableCiliumEndpointSlice indicates if the Cilium Endpoint Slice feature is
	// enabled.
	EnableCiliumEndpointSlice bool
}
