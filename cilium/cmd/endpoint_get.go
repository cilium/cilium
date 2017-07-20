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

	endpointApi "github.com/cilium/cilium/api/v1/client/endpoint"

	"github.com/spf13/cobra"
)

var lbls []string

// endpointGetCmd represents the endpoint_get command
var endpointGetCmd = &cobra.Command{
	Use:     "get ( <endpoint identifier> | -l <endpoint labels> ) ",
	Aliases: []string{"inspect, show"},
	Short:   "Display endpoint information",
	Example: "cilium endpoint get 4598, cilium endpoint get pod-name:default:foobar, cilium endpoint get -l id.baz",
	Run: func(cmd *cobra.Command, args []string) {

		if len(lbls) > 0 && len(args) > 0 {
			Usagef(cmd, "Cannot provide both endpoint ID and labels arguments concurrently")
		}

		if len(lbls) > 0 {
			params := endpointApi.NewGetEndpointParams().WithLabels(lbls)
			if e, err := client.Endpoint.GetEndpoint(params); err != nil {
				Fatalf("Cannot get endpoints for given list of labels %s: %s\n", lbls, err)
			} else if b, err := json.MarshalIndent(e, "", "  "); err != nil {
				Fatalf("Cannot marshal endpoints %s", err.Error())
			} else {
				fmt.Println(string(b))
			}
		} else {
			requireEndpointID(cmd, args)
			eID := args[0]
			if e, err := client.EndpointGet(eID); err != nil {
				Fatalf("Cannot get endpoint %s: %s\n", eID, err)
			} else if b, err := json.MarshalIndent(e, "", "  "); err != nil {
				Fatalf("Cannot marshal endpoint: %s", err.Error())
			} else {
				fmt.Println(string(b))
			}

		}
	},
}

func init() {
	endpointCmd.AddCommand(endpointGetCmd)
	endpointGetCmd.Flags().StringSliceVarP(&lbls, "labels", "l", []string{}, "list of labels")
}
