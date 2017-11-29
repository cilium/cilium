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
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var printJSONGetEndpointHealth bool

// endpointHealthCmd represents the endpoint_healthz command
var endpointHealthCmd = &cobra.Command{
	Use:     "health <endpoint id> [<json>=(enable|disable) ...]",
	Short:   "View endpoint health",
	Example: "cilium endpoint health 5421",
	Run: func(cmd *cobra.Command, args []string) {
		requireEndpointID(cmd, args)
		getEndpointHealth(cmd, args)
	},
}

func init() {
	endpointCmd.AddCommand(endpointHealthCmd)
	endpointHealthCmd.Flags().BoolVarP(&printJSONGetEndpointHealth, "json", "", false, "Print raw json from server")
}

func getEndpointHealth(cmd *cobra.Command, args []string) {
	requireEndpointID(cmd, args)
	eID := args[0]
	epHealth, err := client.EndpointHealthGet(eID)
	if err != nil {
		Fatalf("Cannot get endpoint healthz %s: %s\n", eID, err)
	}

	switch {
	case printJSONGetEndpointHealth:
		result := bytes.Buffer{}
		enc := json.NewEncoder(&result)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(epHealth); err != nil {
			Fatalf("Cannot marshal endpoint healthz: %s", err)
		} else {
			fmt.Println(string(result.Bytes()))
		}
	default:
		w := tabwriter.NewWriter(os.Stdout, 2, 0, 3, ' ', 0)
		fmt.Fprintf(w, "Overall Health:\t%s\n", epHealth.OverallHealth)
		fmt.Fprintf(w, "BPF Health:\t%s\n", epHealth.Bpf)
		fmt.Fprintf(w, "Policy Health:\t%s\n", epHealth.Policy)
		connected := map[bool]string{true: "yes", false: "no"}
		fmt.Fprintf(w, "Connected:\t%s\n", connected[epHealth.Connected])
		w.Flush()
	}
}
