// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import "github.com/spf13/pflag"

type Config struct {
	EnableExperimentalLB bool
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-experimental-lb", def.EnableExperimentalLB, "Enable experimental load-balancing control-plane")
	flags.MarkHidden("enable-experimental-lb")
}

var DefaultConfig = Config{
	EnableExperimentalLB: false,
}
