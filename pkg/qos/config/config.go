// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/spf13/pflag"
)

const (
	// EnableQoS is the name of the option to enable the QoS API.
	EnableQoS = "enable-qos"
)

// Config is the configuration of the QoS API.
type Config struct {
	// EnableQoS enables the QoS API and its CRDs.
	EnableQoS bool `mapstructure:"enable-qos"`
}

// DefaultConfig is the default configuration of the QoS API.
var DefaultConfig = Config{
	EnableQoS: false,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableQoS, def.EnableQoS, "Enable the QoS API and the CiliumQoSMechanism, CiliumQoSClass and CiliumQoSPolicy CRDs")
}
