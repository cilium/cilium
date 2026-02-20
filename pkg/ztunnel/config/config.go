// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/spf13/pflag"
)

var DefaultConfig = Config{
	EnableZTunnel:                  false,
	EndpointEventChannelBufferSize: 1024,
}

// Config is a shared config for all ZTunnel module's cells.
// Note: The operator reads EnableZTunnel directly from the ConfigMap,
// while the agent uses this Config struct for dependency injection.
type Config struct {
	EnableZTunnel                  bool
	EndpointEventChannelBufferSize int `mapstructure:"ztunnel-endpoint-event-channel-buffer-size"`
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-ztunnel", false, "Use zTunnel as Cilium's encryption infrastructure")
	flags.Int("ztunnel-endpoint-event-channel-buffer-size", 1024, "Buffer size for the ztunnel endpoint event channel")
	flags.MarkHidden("ztunnel-endpoint-event-channel-buffer-size")
}
