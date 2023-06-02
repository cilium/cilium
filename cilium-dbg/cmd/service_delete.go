// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var deleteAll bool

func frontendAddressAsID(fa *models.FrontendAddress) string {
	a, err := loadbalancer.NewL3n4AddrFromModel(fa)
	if err != nil {
		Fatalf("Invalid frontend address: %s", err)
	}
	return a.ModelID()
}

// serviceDeleteCmd represents the service_delete command
var serviceDeleteCmd = &cobra.Command{
	Use:   "delete { <service frontend> | --all }",
	Short: "Delete a service",
	Run: func(cmd *cobra.Command, args []string) {
		if deleteAll {
			list, err := client.GetServices()
			if err != nil {
				Fatalf("Cannot get list of services: %s", err)
			}

			for _, svc := range list {
				if svc.Status == nil || svc.Status.Realized == nil {
					log.Error("Skipping service due to empty state")
					continue
				}

				id := frontendAddressAsID(svc.Status.Realized.FrontendAddress)
				if err := client.DeleteServiceID(id); err != nil {
					log.WithError(err).WithField(logfields.ServiceID, id).Error("Cannot delete service")
				}
			}

			return
		}

		frontend := args[0]
		requireServiceID(cmd, args)
		if err := client.DeleteServiceID(frontend); err != nil {
			Fatalf("%s", err)
		}
		fmt.Printf("Service %q deleted successfully\n", frontend)
	},
}

func init() {
	ServiceCmd.AddCommand(serviceDeleteCmd)
	serviceDeleteCmd.Flags().BoolVarP(&deleteAll, "all", "", false, "Delete all services")
}
