// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package shell

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/defaults"
)

const ShellSockPathName = "shell-sock-path"

var DefaultConfig = Config{ShellSockPath: defaults.ShellSockPath}

// Config is the configuration for the shell server.
type Config struct {
	ShellSockPath string
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.String(ShellSockPathName, def.ShellSockPath, "Path to the shell UNIX socket")
}
