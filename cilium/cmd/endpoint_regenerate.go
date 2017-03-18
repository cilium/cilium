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

	"github.com/spf13/cobra"
)

// endpointRegenerateCmd represents the endpoint_regenerate command
var endpointRegenerateCmd = &cobra.Command{
	Use:    "regenerate <endpoint-id>",
	Short:  "Force regeneration of endpoint program",
	PreRun: requireEndpointID,
	Run: func(cmd *cobra.Command, args []string) {
		id := args[0]
		if err := client.EndpointConfigPatch(id, nil); err != nil {
			Fatalf("Cannot regenerate endpoint %s: %s\n", id, err)
		} else {
			fmt.Printf("Endpoint %s successfully regenerated\n", id)
		}
	},
}

func init() {
	endpointCmd.AddCommand(endpointRegenerateCmd)
}
