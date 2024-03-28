// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hooks

import (
	"github.com/cilium/cilium-cli/api"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/cilium-cli/cli"
)

type Hooks struct {
	api.NopHooks
}

func (h *Hooks) InitializeCommand(command *cobra.Command) {
	for _, subcommand := range command.Commands() {
		if subcommand.Name() == "connectivity" {
			command.RemoveCommand(subcommand)
		}
	}
	command.AddCommand(cli.NewCmdConnectivity(h))
}
