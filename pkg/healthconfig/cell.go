// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthconfig

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

const (
	EnableHealthCheckingName         = "enable-health-checking"
	EnableEndpointHealthCheckingName = "enable-endpoint-health-checking"
)

// Cell provides the Cilium health config.
var Cell = cell.Module(
	"cilium-health-config",
	"Cilium health config",
	cell.Config[CiliumHealthConfig](defaultConfig),
)

type Config struct {
	EnableHealthChecking         bool `mapstructure:"enable-health-checking"`
	EnableEndpointHealthChecking bool `mapstructure:"enable-endpoint-health-checking"`
}

var defaultConfig = Config{
	EnableHealthChecking:         true,
	EnableEndpointHealthChecking: true,
}

type CiliumHealthConfig interface {
	cell.Flagger
	IsHealthCheckingEnabled() bool
	IsEndpointHealthCheckingEnabled() bool
}

func (c Config) IsHealthCheckingEnabled() bool {
	return c.EnableHealthChecking
}

func (c Config) IsEndpointHealthCheckingEnabled() bool {
	return c.EnableEndpointHealthChecking
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableHealthCheckingName, c.EnableHealthChecking, "Enable connectivity health checking")
	flags.Bool(EnableEndpointHealthCheckingName, c.EnableEndpointHealthChecking, "Enable connectivity health checking between virtual endpoints")
}
