// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package watch

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/hubble/cmd/common/config"
	"github.com/cilium/cilium/hubble/cmd/common/template"
)

// New creates a new hidden peer command.
func New(vp *viper.Viper) *cobra.Command {
	peerCmd := &cobra.Command{
		Use:     "watch",
		Aliases: []string{"w"},
		Short:   "Watch Hubble objects",
		Hidden:  true, // this command is only useful for development/debugging purposes
	}

	// add config.ServerFlags to the help template as these flags are used by
	// this command
	template.RegisterFlagSets(peerCmd, config.ServerFlags)

	peerCmd.AddCommand(
		newPeerCommand(vp),
	)
	return peerCmd
}
