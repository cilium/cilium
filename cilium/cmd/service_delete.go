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
	"os"
	"strconv"

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
				if err := client.DeleteServiceID(svc.ID); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: Cannot delete service %v: %s",
						svc, err)
				}
			}

			return
		}

		requireServiceID(cmd, args)
		if id, err := strconv.ParseInt(args[0], 0, 64); err != nil {
			Fatalf("%s", err)
		} else {
			if err := client.DeleteServiceID(int64(id)); err != nil {
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
