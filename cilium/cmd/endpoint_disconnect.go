// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// endpointDisconnectCmd represents the endpoint_disconnect command
var endpointDisconnectCmd = &cobra.Command{
	Use:    "disconnect <endpoint-id>",
	Short:  "Disconnect an endpoint from the network",
	PreRun: requireEndpointID,
	Run: func(cmd *cobra.Command, args []string) {
		id := args[0]
		if err := client.EndpointDelete(id); err != nil {
			Fatalf("Cannot disconnect endpoint %s: %s\n", id, err)
		} else {
			fmt.Printf("Endpoint %s successfully disconnected\n", id)
		}
	},
}

func init() {
	endpointCmd.AddCommand(endpointDisconnectCmd)
}
