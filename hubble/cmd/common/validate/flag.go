// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package validate

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// FlagFunc is a function that validates a flag or set of flags of cmd.
type FlagFunc func(cmd *cobra.Command, vp *viper.Viper) error

// FlagFuncs is a combination of multiple flag validation functions.
var FlagFuncs []FlagFunc

// Flags validates flags for the given command.
func Flags(cmd *cobra.Command, vp *viper.Viper) error {
	for _, fn := range FlagFuncs {
		if err := fn(cmd, vp); err != nil {
			return fmt.Errorf("invalid flag(s): %w", err)
		}
	}
	return nil
}
