// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package neighbor

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/datapath/xdp"
)

type neighborConfig struct {
	EnableL2NeighDiscovery bool
}

func (c neighborConfig) Flags(fs *pflag.FlagSet) {
	fs.Bool("enable-l2-neigh-discovery", false, "Enables L2 neighbor discovery used by kube-proxy-replacement and IPsec")
}

type CommonConfig struct {
	Enabled              bool
	ARPPingKernelManaged func() error
}

func newCommonConfig(
	config neighborConfig,
	xdpConfig xdp.Config,
	lifecycle cell.Lifecycle,
) *CommonConfig {
	return &CommonConfig{
		Enabled:              config.EnableL2NeighDiscovery || !xdpConfig.Disabled(),
		ARPPingKernelManaged: probes.HaveManagedNeighbors,
	}
}

// NewCommonTestConfig returns a function that creates a commonConfig with the specified parameters.
func NewCommonTestConfig(
	enableL2NeighDiscovery bool,
	arpPingKernelManaged bool,
) func() *CommonConfig {
	return func() *CommonConfig {
		return &CommonConfig{
			Enabled: enableL2NeighDiscovery,
			ARPPingKernelManaged: func() error {
				if arpPingKernelManaged {
					return nil
				}

				return probes.ErrNotSupported
			},
		}
	}
}
