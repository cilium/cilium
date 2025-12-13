// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namespace

import "github.com/spf13/pflag"

var DefaultConfig = Config{
	GlobalNamespacesByDefault: true,
}

type Config struct {
	// GlobalNamespacesByDefault marks all namespaces as global by default unless overridden by annotation
	GlobalNamespacesByDefault bool `mapstructure:"clustermesh-default-global-namespace"`
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(
		"clustermesh-default-global-namespace",
		cfg.GlobalNamespacesByDefault,
		"Mark all namespaces as global by default unless overridden by annotation",
	)
	flags.MarkHidden("clustermesh-default-global-namespace")
}
