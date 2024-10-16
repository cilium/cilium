// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package cpumap

import (
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	"github.com/tklauser/numcpus"

	"github.com/cilium/cilium/pkg/datapath/xdp"
)

// userCfg allows for users to specify configuration options on
// the command line.
type userCfg struct {
	XdpCpumapQSize uint32
}

var defaultUserConfig = userCfg{
	// TODO: This is picked based off of some initial testing, but
	// it should probably be tuned based off of the system's specs.
	XdpCpumapQSize: 255,
}

func (u userCfg) Flags(flags *pflag.FlagSet) {
	xdpCPUMapQSizeFlagName := "xdp-cpumap-qsize"
	flags.Uint32(xdpCPUMapQSizeFlagName, u.XdpCpumapQSize, "Redirection queue size for the XDP cpumap.")
}

// Config represents the materialized cpumap configuration to be
// used, depending on its required use by other features.
type Config struct {
	numCPUs uint
	qsize   uint32
	enabled bool
}

// If the cpumap is enabled or not.
func (c Config) Enabled() bool { return c.enabled }

// The number of CPUs that are enabled on the node.
func (c Config) NumCPUs() uint { return c.numCPUs }

// The configured qsize to use for each cpu.
func (c Config) QSize() uint32 { return c.qsize }

type enabler struct {
	enable bool
}

// EnablerOut allows requesting to enable the cpu map.
type EnablerOut struct {
	cell.Out
	Enabler enabler `group:"request-cpu-map"`
}

// NewEnabler returns an object to be injected into the hive to request
// that the cpu map is loaded and made available to the datapath.
func NewEnabler(enable bool) EnablerOut {
	return EnablerOut{Enabler: enabler{enable}}
}

type newConfigIn struct {
	cell.In
	// XDPConfig is the materialized XDP configuration. This is used for
	// sanity checking that XDP is enabled, since it doesn't make sense to
	// enable the cpumap if XDP is disabled.
	XDPConfig xdp.Config
	// Enablers determine if the cpumap should be enabled or not.
	// The cpumap will be enabled if at least one enabler is given which
	// has the field "enable" set to true.
	Enablers []enabler `group:"request-cpu-map"`
	// UserCfg is the parsed user provided configuration (ie cli flags).
	// This is used to determine runtime configurables, such as the qsize.
	UserCfg userCfg
}

func newConfig(in newConfigIn) (Config, error) {
	cfg := Config{
		enabled: false,
		qsize:   0,
		numCPUs: 0,
	}

	for _, e := range in.Enablers {
		if e.enable {
			cfg.enabled = true
		}
	}
	if !cfg.enabled {
		return cfg, nil
	}

	// Sanity check.
	if in.XDPConfig.Disabled() {
		return cfg, fmt.Errorf("the XDP cpu redirect map has been requested to be enabled but XDP is disabled")
	}

	// Get the number of CPUs available on the node.
	// Note this is destinctly different compared to the number
	// of possible CPUs.
	// TODO: Detect and tolerate the number of CPUs changing during runtime.
	onlineCPUs, err := numcpus.GetOnline()
	if err != nil {
		return cfg, fmt.Errorf("unable to get the number of online CPUs: %w", err)
	}
	cfg.numCPUs = uint(onlineCPUs)

	// TODO: Just picking a sensible default for now that worked well in testing, but
	// this should by dynamic based on the available system memory.
	cfg.qsize = in.UserCfg.XdpCpumapQSize

	return cfg, nil
}
