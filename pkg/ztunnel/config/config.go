package config

import "github.com/spf13/pflag"

// Shared config for all ZTunnel module's cells.
type Config struct {
	EnableZTunnel bool
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-ztunnel", false, "Use zTunnel as Cilium's encryption infrastructure")
}
