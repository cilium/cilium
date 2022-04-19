// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/loadbalancer"
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

		slice := []string{}
		for _, be := range svc.Status.Realized.BackendAddresses {
			if bea, err := loadbalancer.NewL3n4AddrFromBackendModel(be); err != nil {
				slice = append(slice, fmt.Sprintf("invalid backend: %+v", be))
			} else {
				slice = append(slice, bea.String())
			}
		}

		if command.OutputOption() {
			if err := command.PrintOutput(svc); err != nil {
				os.Exit(1)
			}
			return
		}

		if fea, err := loadbalancer.NewL3n4AddrFromModel(svc.Status.Realized.FrontendAddress); err != nil {
			fmt.Fprintf(os.Stderr, "invalid frontend model: %s", err)
		} else {
			fmt.Printf("%s =>\n", fea.String())
		}

		for i, be := range slice {
			fmt.Printf("\t\t%d => %s (%d)\n", i+1, be, svc.Status.Realized.ID)
		}
	},
}

func init() {
	serviceCmd.AddCommand(serviceGetCmd)
	command.AddOutputOption(serviceGetCmd)
}
