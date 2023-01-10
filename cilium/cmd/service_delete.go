// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

var deleteAll bool

// serviceDeleteCmd represents the service_delete command
var serviceDeleteCmd = &cobra.Command{
	Use:   "delete { <service id> | --all }",
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

				if err := client.DeleteServiceID(svc.Status.Realized.ID); err != nil {
					log.WithError(err).WithField(logfields.ServiceID, svc.Status.Realized.ID).Error("Cannot delete service")
				}
			}

			return
		}

		warnIdTypeDeprecation()

		requireServiceID(cmd, args)
		if id, err := strconv.ParseInt(args[0], 0, 64); err != nil {
			Fatalf("%s", err)
		} else {
			if err := client.DeleteServiceID(id); err != nil {
				Fatalf("%s", err)
			}

			fmt.Printf("Service %d deleted successfully\n", id)
		}
	},
}

func init() {
	serviceCmd.AddCommand(serviceDeleteCmd)
	serviceDeleteCmd.Flags().BoolVarP(&deleteAll, "all", "", false, "Delete all services")
}
