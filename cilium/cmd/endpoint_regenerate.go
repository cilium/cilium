// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// endpointRegenerateCmd represents the endpoint_regenerate command
var endpointRegenerateCmd = &cobra.Command{
	Use:   "regenerate <endpoint-id>",
	Short: "Force regeneration of endpoint program",
	PreRun: func(cmd *cobra.Command, args []string) {
		log.WithFields(logrus.Fields{
			logfields.URL:         "https://github.com/cilium/cilium/issues/25948",
			logfields.HelpMessage: "For more information, see the linked URL.",
		}).Warn("This command is deprecated and will be removed in Cilium v1.15.")
		requireEndpointID(cmd, args)
	},
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
	EndpointCmd.AddCommand(endpointRegenerateCmd)
}
