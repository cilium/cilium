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

	"github.com/cilium/cilium/common/types"

	"github.com/spf13/cobra"
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
			Fatalf("Cannot get service: %s\n", err)
		}

		slice := []string{}
		for _, be := range svc.BackendAddresses {
			if bea, err := types.NewL3n4AddrFromBackendModel(be); err != nil {
				slice = append(slice, fmt.Sprintf("invalid backend: %+v", be))
			} else {
				slice = append(slice, bea.String())
			}
		}

		if fea, err := types.NewL3n4AddrFromModel(svc.FrontendAddress); err != nil {
			fmt.Fprintf(os.Stderr, "invalid frontend model: %s", err)
		} else {
			fmt.Printf("%s =>\n", fea.String())
		}

		for i, be := range slice {
			fmt.Printf("\t\t%d => %s (%d)\n", i+1, be, svc.ID)
		}
	},
}

func init() {
	serviceCmd.AddCommand(serviceGetCmd)
}
