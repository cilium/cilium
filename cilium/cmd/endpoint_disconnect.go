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

// endpointDisconnectCmd represents the endpoint_disconnect command
var endpointDisconnectCmd = &cobra.Command{
	Use:    "disconnect <endpoint-id>",
	Short:  "Disconnect an endpoint from the network",
	PreRun: requireEndpointID,
	Run: func(cmd *cobra.Command, args []string) {
		id := args[0]
		if err := client.EndpointDelete(id); err != nil {
			Fatalf("Cannot disconnect endpoint %s: %s\n", id, err)
		} else {
			fmt.Printf("Endpoint %s successfully disconnected\n", id)
		}
	},
}

func init() {
	endpointCmd.AddCommand(endpointDisconnectCmd)
}
