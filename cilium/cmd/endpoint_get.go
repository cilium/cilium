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
	"os"

	endpointApi "github.com/cilium/cilium/api/v1/client/endpoint"
	"github.com/cilium/cilium/api/v1/models"
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
		var endpointInst []*models.Endpoint

		if len(lbls) > 0 {
			params := endpointApi.NewGetEndpointParams().WithLabels(lbls)
			result, err := client.Endpoint.GetEndpoint(params)
			if err != nil {
				Fatalf("Cannot get endpoints for given list of labels %s: %s\n", lbls, err)
			}
			endpointInst = result.Payload
		} else {
			requireEndpointID(cmd, args)
			eID := args[0]
			result, err := client.EndpointGet(eID)
			if err != nil {
				Fatalf("Cannot get endpoint %s: %s\n", eID, err)
			}
			endpointInst = append(endpointInst, result)
		}

		if len(dumpOutput) > 0 {
			if err := OutputPrinter(endpointInst); err != nil {
				os.Exit(1)
			}
			return
		}

		if result, err := json.MarshalIndent(endpointInst, "", "  "); err != nil {
			Fatalf("Cannot marshal endpoints %s", err.Error())
		} else {
			fmt.Println(string(result))
		}
	},
}

func init() {
	endpointCmd.AddCommand(endpointGetCmd)
	endpointGetCmd.Flags().StringSliceVarP(&lbls, "labels", "l", []string{}, "list of labels")
	AddMultipleOutput(endpointGetCmd)
}
