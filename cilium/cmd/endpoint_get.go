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
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

// endpointGetCmd represents the endpoint_get command
var endpointGetCmd = &cobra.Command{
	Use:     "get <endpoint-id>",
	Aliases: []string{"inspect, show"},
	Short:   "Display endpoint information",
	Example: "cilium endpoint get 4598",
	PreRun:  requireEndpointID,
	Run: func(cmd *cobra.Command, args []string) {
		id := args[0]
		if e, err := client.EndpointGet(id); err != nil {
			Fatalf("Cannot get endpoint %s: %s\n", id, err)
		} else if b, err := json.MarshalIndent(e, "", "  "); err != nil {
			Fatalf("Cannot marshal endpoing: %s", err.Error())
		} else {
			fmt.Println(string(b))
		}
	},
}

func init() {
	endpointCmd.AddCommand(endpointGetCmd)
}
