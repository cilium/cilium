// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive/cell"
)

const (
	// CIDWriteQPSLimit is the rate limit per second for the CID work queue to
	// process CID events that result in CID write (Create, Update, Delete)
	// requests to the kube-apiserver.
	CIDWriteQPSLimit = "cid-write-qps-limit"

	// CIDWriteQPSBurst is the burst rate per second used with CIDWriteQPSLimit
	// for the CID work queue to process CID events that result in CID write
	// (Create, Update, Delete) requests to the kube-apiserver.
	CIDWriteQPSBurst = "cid-write-qps-burst"
)

// Cell is a cell that implements a Cilium Identity Controller. The controller
// subscribes to Cilium Identity, Cilium Endpoint Slices, Pods and Namespace
// events and reconciles the state of cilium identities in the cluster.
var Cell = cell.Module(
	"k8s-cid-controller",
	"Cilium Identity Controller",
	cell.Config(defaultConfig),
	cell.Invoke(registerController),
	cell.Metric(NewMetrics),
)

type Config struct {
	CIDQueueQPSLimit   float64 `mapstructure:"cid-write-qps-limit"`
	CIDQueueBurstLimit int     `mapstructure:"cid-write-qps-burst"`
}

var defaultConfig = Config{
	CIDQueueQPSLimit:   defaultCIDQueueQPSLimit,
	CIDQueueBurstLimit: defaultCIDQueueBurstLimit,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Float64(CIDWriteQPSLimit, def.CIDQueueQPSLimit, "CID work queue rate limit")
	flags.Int(CIDWriteQPSBurst, def.CIDQueueBurstLimit, "CID work queue burst rate")
}

// SharedConfig contains the configuration that is shared between
// this module and others.
// It is a temporary solution meant to avoid polluting this module with a direct
// dependency on global operator and daemon configurations.
type SharedConfig struct {
	// EnableOperatorManageCIDs enables operator to manage Cilium Identities by
	// running a Cilium Identity controller.
	EnableOperatorManageCIDs bool

	// EnableCiliumEndpointSlice indicates if the Cilium Endpoint Slice feature is
	// enabled.
	EnableCiliumEndpointSlice bool
}
