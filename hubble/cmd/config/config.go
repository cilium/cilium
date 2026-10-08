// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package config

import (
	"slices"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// New config command.
func New(vp *viper.Viper) *cobra.Command {
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Modify or view hubble config",
		Long: `Config allows to modify or view the hubble configuration. Global hubble options
can be set via flags, environment variables or a configuration file. The
following precedence order is used:

1. Flag
2. Environment variable
3. Configuration file
4. Default value

The "config view" subcommand provides a merged view of the configuration. The
"config set" and "config reset" subcommand modify values in the configuration
file.

Environment variable names start with HUBBLE_ followed by the flag name
capitalized where eventual dashes ('-') are replaced by underscores ('_').
For example, the environment variable that corresponds to the "--server" flag
is HUBBLE_SERVER. The environment variable for "--tls-allow-insecure" is
HUBBLE_TLS_ALLOW_INSECURE and so on.`,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			// override root persistent pre-run to avoid flag/config checks
			// as we want to be able to modify/view the config even if it is
			// invalid
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	configCmd.AddCommand(
		newGetCommand(vp),
		newResetCommand(vp),
		newSetCommand(vp),
		newViewCommand(vp),
	)
	return configCmd
}

func isKey(vp *viper.Viper, key string) bool {
	return slices.Contains(vp.AllKeys(), key)
}
