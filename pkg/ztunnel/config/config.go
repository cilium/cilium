package config

import (
	"github.com/spf13/pflag"
)

const (
	DefaultZtunnelUnixAddress = "/var/run/cilium/ztunnel.sock"
)

// Shared config for all ZTunnel module's cells.
type Config struct {
	EnableZTunnel bool
	ZDSUnixAddr   string `mapstructure:"ztunnel-zds-unix-addr"`
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-ztunnel", false, "Use zTunnel as Cilium's encryption infrastructure")
	flags.String("ztunnel-zds-unix-addr", DefaultZtunnelUnixAddress, "Unix address for zds server")
}
