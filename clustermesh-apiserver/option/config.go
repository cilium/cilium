// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"time"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/option"
)

const (
	// PprofAddressAPIServer is the default value for pprof in the clustermesh-apiserver
	PprofAddressAPIServer = "localhost"

	// PprofPortAPIServer is the default value for pprof in the clustermesh-apiserver
	PprofPortAPIServer = 6063
)

// LegacyClusterMeshConfig is used to register the flags for the options which
// are still accessed through the global DaemonConfig variable.
type LegacyClusterMeshConfig struct {
	Debug          bool
	CRDWaitTimeout time.Duration
}

var DefaultLegacyClusterMeshConfig = LegacyClusterMeshConfig{
	Debug:          false,
	CRDWaitTimeout: 5 * time.Minute,
}

func (def LegacyClusterMeshConfig) Flags(flags *pflag.FlagSet) {
	flags.BoolP(option.DebugArg, "D", def.Debug, "Enable debugging mode")
	flags.Duration(option.CRDWaitTimeout, def.CRDWaitTimeout, "Cilium will exit if CRDs are not available within this duration upon startup")
}
