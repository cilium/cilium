// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package hubblecell

import (
	"github.com/spf13/pflag"
)

type config struct {
	// EnableHubble specifies whether to enable the hubble server.
	EnableHubble bool `mapstructure:"enable-hubble"`
}

var defaultConfig = config{
	EnableHubble: true,
}

func (def config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-hubble", def.EnableHubble, "Enable hubble server")
}

func (cfg *config) normalize() {
}

func (cfg config) validate() error {
	return nil
}
