// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package config

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newResetCommand(vp *viper.Viper) *cobra.Command {
	return &cobra.Command{
		Use:   "reset [KEY]",
		Short: "Reset all or an individual value in the hubble config file",
		Long: "Reset all or an individual value in the hubble config file.\n" +
			"When KEY is provided, this command is equivalent to 'set KEY'.\n" +
			"If KEY is not provided, all values are reset to their default value.",
		ValidArgs: vp.AllKeys(),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch len(args) {
			case 1:
				return runSet(cmd, vp, args[0], "")
			case 0:
				return runReset(cmd, vp)
			default:
				return fmt.Errorf("invalid arguments: reset requires exactly 0 or 1 argument: got '%s'", strings.Join(args, " "))
			}
		},
	}
}

func runReset(cmd *cobra.Command, vp *viper.Viper) error {
	for _, key := range vp.AllKeys() {
		if err := runSet(cmd, vp, key, ""); err != nil {
			return err
		}
	}
	return nil
}
