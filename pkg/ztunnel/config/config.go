// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/spf13/pflag"
)

const (
	DefaultZtunnelUnixAddress = "/var/run/cilium/ztunnel.sock"
	DefaultXDSUnixAddress     = "/var/run/cilium/xds.sock"
)

var DefaultConfig = Config{
	EnableZTunnel: false,
	ZDSUnixAddr:   DefaultZtunnelUnixAddress,
	XDSUnixAddr:   DefaultXDSUnixAddress,
}

// Config is a shared config for all ZTunnel module's cells.
// Note: The operator reads EnableZTunnel directly from the ConfigMap,
// while the agent uses this Config struct for dependency injection.
type Config struct {
	EnableZTunnel bool
	EnableSPIRE   bool
	ZDSUnixAddr   string `mapstructure:"ztunnel-zds-unix-addr"`
	XDSUnixAddr   string `mapstructure:"ztunnel-xds-unix-addr"`
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-ztunnel", false, "Use zTunnel as Cilium's encryption infrastructure")
	flags.Bool("enable-ztunnel-spire", false, "Use SPIRE for zTunnel certificate management instead of the built-in CA")
	flags.String("ztunnel-zds-unix-addr", DefaultZtunnelUnixAddress, "Unix address for zds server")
	flags.String("ztunnel-xds-unix-addr", DefaultXDSUnixAddress, "Unix address for xds server")
}
