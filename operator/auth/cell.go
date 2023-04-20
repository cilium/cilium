// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/operator/auth/spire"
	"github.com/cilium/cilium/pkg/hive/cell"
)

const (
	MTLSEnabled = "mesh-auth-mtls-enabled"
)

var Cell = cell.Module(
	"auth-identity",
	"Cilium mTLS Identity management",
	spire.Cell,
	cell.Config(Config{}),
	cell.Invoke(registerIdentityWatcher),
)

// Config contains the configuration for the identity-gc.
type Config struct {
	Enabled bool `mapstructure:"mesh-auth-mtls-enabled"`
}

// Flags implements cell.Flagger interface.
func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(MTLSEnabled, cfg.Enabled, "Enable mTLS authentication in Cilium")
}
