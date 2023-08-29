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
}

func (def KVStoreMeshConfig) Flags(flags *pflag.FlagSet) {
	flags.BoolP(option.DebugArg, "D", def.Debug, "Enable debugging mode")
}
