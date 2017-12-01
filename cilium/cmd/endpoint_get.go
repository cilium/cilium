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
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"

	endpointApi "github.com/cilium/cilium/api/v1/client/endpoint"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var lbls []string

// L4Policy is nested JSON, so search 'result' for strings that have
// backslashes inside, and interpet the JSON.
func expandNestedJSON(result bytes.Buffer) bytes.Buffer {
	re := regexp.MustCompile(`"[^"\\]*\\.*[^\\]"`)
	for {
		var (
			loc    []int
			indent string
		)

		// Search for nested JSON; if we don't find any, then break.
		resBytes := result.Bytes()
		if loc = re.FindIndex(resBytes); loc == nil {
			break
		}

		// Determine the current indentation
		for i := 0; i < loc[0]-1; i++ {
			idx := loc[0] - i - 1
			if resBytes[idx] != ' ' {
				break
			}
			indent = fmt.Sprintf("%s ", indent)
		}

		// Unquote the nested json, decode it into a map, then marshal.
		m := make(map[string]interface{})
		s, _ := strconv.Unquote(string(resBytes[loc[0]:loc[1]]))
		nested := bytes.NewBufferString(s)
		dec := json.NewDecoder(nested)
		if err := dec.Decode(&m); err != nil {
			Fatalf("Failed to decode nested JSON: %s", err.Error())
		}
		out, err := json.MarshalIndent(m, indent, "  ")
		if err != nil {
			Fatalf("Cannot marshal nested JSON: %s", err.Error())
		}

		nextResult := bytes.Buffer{}
		nextResult.Write(resBytes[0:loc[0]])
		nextResult.WriteString(string(out))
		nextResult.Write(resBytes[loc[1]:])
		result = nextResult
	}

	return result
}

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

		if viper.GetBool("json") {
			result, err := json.MarshalIndent(endpointInst, "", "  ")
			if err != nil {
				Fatalf("Cannot marshal endpoints: %s", err.Error())
			}
			fmt.Printf("%s\n", result)
		} else {
			result := bytes.Buffer{}
			enc := json.NewEncoder(&result)
			enc.SetEscapeHTML(false)
			enc.SetIndent("", "  ")
			if err := enc.Encode(endpointInst); err != nil {
				Fatalf("Cannot marshal endpoints %s", err.Error())
			}

			result = expandNestedJSON(result)
			fmt.Println(string(result.Bytes()))
		}
	},
}

func init() {
	endpointCmd.AddCommand(endpointGetCmd)
	endpointGetCmd.Flags().StringSliceVarP(&lbls, "labels", "l", []string{}, "list of labels")
	AddMultipleOutput(endpointGetCmd)
}
