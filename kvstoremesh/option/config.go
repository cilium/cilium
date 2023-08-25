// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/option"
)

const (
	// PprofAddress is the default value for pprof in kvstoremesh
	PprofAddress = "localhost"

	// PprofPort is the default value for pprof in kvstoremesh
	PprofPort = 6064
)

// Config is the KVStoreMeshConfig configuration.
type KVStoreMeshConfig struct {
	Debug bool

	ClusterName string
	ClusterID   uint32
}

func (def KVStoreMeshConfig) Flags(flags *pflag.FlagSet) {
	flags.BoolP(option.DebugArg, "D", def.Debug, "Enable debugging mode")
	flags.String(option.ClusterName, def.ClusterName, "Name of the cluster")
	flags.Uint32(option.ClusterIDName, def.ClusterID, "Unique identifier of the cluster")
}
