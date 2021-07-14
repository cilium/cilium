// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2019 Authors of Cilium

package cmd

import (
	"fmt"

	"github.com/cilium/cilium/api/v1/models"

	"github.com/spf13/cobra"
)

// endpointRegenerateCmd represents the endpoint_regenerate command
var endpointRegenerateCmd = &cobra.Command{
	Use:    "regenerate <endpoint-id>",
	Short:  "Force regeneration of endpoint program",
	PreRun: requireEndpointID,
	Run: func(cmd *cobra.Command, args []string) {
		id := args[0]
		cfg := &models.EndpointConfigurationSpec{}
		if err := client.EndpointConfigPatch(id, cfg); err != nil {
			Fatalf("Cannot regenerate endpoint %s: %s\n", id, err)
		} else {
			fmt.Printf("Endpoint %s successfully regenerated\n", id)
		}
	},
}

func init() {
	endpointCmd.AddCommand(endpointRegenerateCmd)
}
