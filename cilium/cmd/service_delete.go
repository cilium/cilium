// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"strconv"

	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/spf13/cobra"
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
