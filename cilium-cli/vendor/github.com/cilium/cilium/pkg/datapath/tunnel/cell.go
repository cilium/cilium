// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tunnel

import (
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/option"
)

// Cell is a cell that provides the parameters for the Cilium tunnel,
// based on user configuration and requests from external modules.
var Cell = cell.Module(
	"datapath-tunnel-config",
	"Tunneling configurations",

	cell.Config(userCfg{TunnelProtocol: defaults.TunnelProtocol}),

	cell.Provide(
		newConfig,

		// Provide the datapath options.
		Config.datapathConfigProvider,

		// Enable tunnel configuration when it is the primary routing mode.
		func(dcfg *option.DaemonConfig) EnablerOut {
			return NewEnabler(dcfg.TunnelingEnabled())
		},

		// Enable tunnel configuration when DSR Geneve is enabled (this is currently
		// handled here, as the corresponding logic has not yet been modularized).
		func(dcfg *option.DaemonConfig) EnablerOut {
			return NewEnabler(
				(dcfg.EnableNodePort ||
					dcfg.KubeProxyReplacement == option.KubeProxyReplacementStrict ||
					dcfg.KubeProxyReplacement == option.KubeProxyReplacementTrue) &&
					dcfg.LoadBalancerUsesDSR() &&
					dcfg.LoadBalancerDSRDispatch == option.DSRDispatchGeneve,
				// The datapath logic takes care of the MTU overhead. So no need to
				// take it into account here.
				// See encap_geneve_dsr_opt[4,6] in nodeport.h
				WithoutMTUAdaptation(),
			)
		},

		// Enable tunnel configuration when High Scale IPCache is enabled (this is
		// currently handled here, as the corresponding logic has not yet been modularized).
		func(dcfg *option.DaemonConfig) EnablerOut {
			return NewEnabler(dcfg.EnableHighScaleIPcache)
		},
	),
)
