// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsecrps

import (
	"errors"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	dpcfgdef "github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/xdp"
	"github.com/cilium/cilium/pkg/maps/cpumap"
	"github.com/cilium/cilium/pkg/option"
)

// userFlags represents the options that the user provided to the daemon
// to control the IPSec RPS configuration
type userFlags struct {
	EnableIpsecAcceleration bool
}

func (u userFlags) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-ipsec-acceleration", u.EnableIpsecAcceleration, "Enable acceleration for IPSec using RPS (experimental).")
}

var defaultUserFlags = userFlags{
	EnableIpsecAcceleration: false,
}

// userCfg represents the materialized user configuration for IPSec RPS
// based on the provided flags.
type userCfg struct {
	Enabled bool
}

type newUserCfgOut struct {
	cell.Out
	XDPEnabler    xdp.EnablerOut
	UserCfg       userCfg
	CPUMapEnabler cpumap.EnablerOut
}

func newUserCfg(flags userFlags) newUserCfgOut {
	cfg := userCfg{Enabled: false}
	// The XDP configuration gives no precedence to the disabled mode,
	// meaning returning an enabler with the disabled mode here won't
	// impact other features which require XDP to be enabled. If they
	// return an enabler that requests XDP is enabled, the enabler returned
	// here will essentially be discarded.
	xdpEnabler := xdp.NewEnabler(xdp.AccelerationModeDisabled)
	cpumapEnabler := cpumap.NewEnabler(false)

	if flags.EnableIpsecAcceleration {
		cfg = userCfg{Enabled: true}
		xdpEnabler = xdp.NewEnabler(
			xdp.AccelerationModeNative,
			// Cause startup to bail if XDP cannot be enabled in native mode.
			// Native is required for performance reasons.
			xdp.WithEnforceXDPNative("required for accelerated IPSec with RPS"),
		)
		cpumapEnabler = cpumap.NewEnabler(true)
	}

	return newUserCfgOut{
		UserCfg:       cfg,
		XDPEnabler:    xdpEnabler,
		CPUMapEnabler: cpumapEnabler,
	}
}

// Config is the materialized IPSec RPS configuration.
type Config struct {
	enabled bool
}

// newConfigIn represents the dependencies required by the IPSec RPS configuration.
type newConfigIn struct {
	cell.In
	// Dcfg is the (legacy) materialized daemon configuration. This is used to
	// read the encryption mode and validate IPSec is enabled.
	Dcfg *option.DaemonConfig
	// XDPCfg is the materialized XDP configuration. This is used to ensure that
	// the materialized XDP config is native. This check **should** be provided by
	// the validator which is added to the enabler returned from newUserCfg, but
	// it's an easy check to perform to catch a potential bug. Regardless, this
	// is here to inform the dependency graph that the XDP config needs to be
	// determined before the IPSec RPS config can be created.
	XDPCfg xdp.Config
	// TunnelCfg is the materialized tunneling configuration. This is used to ensure
	// that tunneling is disabled, as IPSec RPS is not currently compatible
	// with any form of tunneling enabled within the datapath.
	TunnelCfg tunnel.Config
	// CPUMapCfg is the materialized CPUMap configuration. This is used to ensure
	// that the CPUMap has been enabled, as the IPSec RPS feature cannot function
	// without it.
	CPUMapCfg cpumap.Config
	// Cfg is the user provided configuration options. This is used to determine
	// if the user has requested IPSec RPS to be enabled.
	Cfg userCfg
}

func newConfig(in newConfigIn) (Config, error) {
	if !in.Cfg.Enabled {
		return Config{enabled: false}, nil
	}

	// Assertions
	// Is IPSec enabled?
	if !in.Dcfg.EncryptionEnabled() || !in.Dcfg.EnableIPSec {
		return Config{}, fmt.Errorf("ipsec rps can only be enabled if IPSec is enabled")
	}
	// Is the XDP mode native?
	if in.XDPCfg.Disabled() || in.XDPCfg.AccelerationMode() != xdp.AccelerationModeNative {
		return Config{}, errors.New("ipsec rps can only be enabled if XDP is enabled in native mode")
	}
	// Is the CPUMap enabled?
	if !in.CPUMapCfg.Enabled() {
		return Config{}, errors.New("ipsec rps can only be enabled if the cpu map is enabled")
	}
	// Is tunneling disabled?
	if in.TunnelCfg.Protocol() != tunnel.Disabled {
		return Config{}, errors.New("ipsec rps can only be enabled if tunneling is disabled")
	}

	return Config{enabled: true}, nil
}

func (cfg Config) Enabled() bool { return cfg.enabled }

func (cfg Config) datapathConfigProvider() dpcfgdef.NodeOut {
	defines := make(dpcfgdef.Map)

	if cfg.Enabled() {
		defines["ENABLE_IPSEC_RPS"] = "1"
	}

	return dpcfgdef.NodeOut{NodeDefines: defines}
}
