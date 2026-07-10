// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package shell

import (
	"github.com/spf13/pflag"
)

const ShellSockPathName = "shell-sock-path"

var DefaultConfig = Config{ShellSockPath: ""}

// Config is the configuration for the shell server.
type Config struct {
	ShellSockPath string
}

// Flags adds flags for Config when running the shell server Cell.
func (def Config) Flags(flags *pflag.FlagSet) {
	flags.String(ShellSockPathName, def.ShellSockPath, "Path to the shell UNIX socket")
}

// Parse the config from the flags.
func (cfg *Config) Parse(flags *pflag.FlagSet) (err error) {
	cfg.ShellSockPath, err = flags.GetString(ShellSockPathName)
	return err
}
