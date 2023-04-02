// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"
)

// serviceGetCmd represents the service_get command
var serviceGetCmd = &cobra.Command{
	Use:    "get <service id>",
	Short:  "Display service information",
	PreRun: requireServiceID,
	Run: func(cmd *cobra.Command, args []string) {
		svcIDstr := args[0]
		id, err := strconv.ParseInt(svcIDstr, 0, 64)
		if err != nil {
			Fatalf("Unable to parse service ID: %s", svcIDstr)
		}

		svc, err := client.GetServiceID(id)
		if err != nil {
			Fatalf("Cannot get service '%v': %s\n", id, err)
		}
		if svc.Status == nil || svc.Status.Realized == nil {
			Fatalf("Cannot get service '%v': empty response\n", id)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(svc); err != nil {
				os.Exit(1)
			}
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
		printServiceList(w, []*models.Service{svc})
	},
}

func init() {
	serviceCmd.AddCommand(serviceGetCmd)
	command.AddOutputOption(serviceGetCmd)
}
