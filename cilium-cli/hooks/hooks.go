// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hooks

import (
	"github.com/cilium/cilium-cli/api"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/cilium-cli/cli"
)

type Hooks struct {
	api.NopHooks
}

func (h *Hooks) InitializeCommand(command *cobra.Command) {
	// The connectivity command is pointing to a version that is vendored in the
	// cilium-cli repo. Remove it and replace it with the local connectivity
	// package.
	for _, subcommand := range command.Commands() {
		if subcommand.Name() == "connectivity" {
			command.RemoveCommand(subcommand)
		}
	}
	command.AddCommand(cli.NewCmdConnectivity(h))
}
