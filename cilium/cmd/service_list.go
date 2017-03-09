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
	"sort"

	"github.com/cilium/cilium/common/types"

	"github.com/spf13/cobra"
)

// serviceListCmd represents the service_list command
var serviceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List services",
	Run: func(cmd *cobra.Command, args []string) {
		listServices()
	},
}

func init() {
	serviceCmd.AddCommand(serviceListCmd)

}

func listServices() {
	list, err := client.GetServices()
	if err != nil {
		Fatalf("Cannot get services list: %s", err)
	}

	svcs := map[string][]string{}
	for _, svc := range list {
		besWithID := []string{}
		for i, be := range svc.BackendAddresses {
			beA, err := types.NewL3n4AddrFromBackendModel(be)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error parsing backend %+v", be)
				continue
			}
			var str string
			if be.Weight != 0 {
				str = fmt.Sprintf("%d => %s (W: %d, ID: %d)", i+1, beA.String(), be.Weight, svc.ID)
			} else {
				str = fmt.Sprintf("%d => %s (%d)", i+1, beA.String(), svc.ID)
			}
			besWithID = append(besWithID, str)
		}

		feA, err := types.NewL3n4AddrFromModel(svc.FrontendAddress)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing frontend %+v", svc.FrontendAddress)
			continue
		}
		svcs[feA.String()] = besWithID
	}

	var svcsKeys []string
	for k := range svcs {
		svcsKeys = append(svcsKeys, k)
	}
	sort.Strings(svcsKeys)

	for _, svcKey := range svcsKeys {
		fmt.Printf("%s =>\n", svcKey)
		for _, be := range svcs[svcKey] {
			fmt.Printf("\t\t%s\n", be)
		}
	}
}
