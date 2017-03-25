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
	"text/tabwriter"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/endpoint"

	"github.com/spf13/cobra"
)

var noHeaders bool

// endpointListCmd represents the endpoint_list command
var endpointListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all endpoints",
	Run: func(cmd *cobra.Command, args []string) {
		listEndpoints()
	},
}

func init() {
	endpointCmd.AddCommand(endpointListCmd)
	endpointListCmd.Flags().BoolVar(&noHeaders, "no-headers", false, "Do not print headers")
}

func listEndpoint(w *tabwriter.Writer, ep *models.Endpoint, id string, label string) {
	fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t\n",
		ep.ID, id, label, ep.Addressing.IPV6, ep.Addressing.IPV4, ep.State)
}

func listEndpoints() {
	eps, err := client.EndpointList()
	if err != nil {
		Fatalf("cannot get endpoint list: %s\n", err)
	}

	endpoint.OrderEndpointAsc(eps)

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

	const (
		labelsIDTitle  = "IDENTITY"
		labelsDesTitle = "LABELS (source:key[=value])"
		ipv6Title      = "IPv6"
		ipv4Title      = "IPv4"
		endpointTitle  = "ENDPOINT"
		statusTitle    = "STATUS"
	)

	if !noHeaders {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t\n",
			endpointTitle, labelsIDTitle, labelsDesTitle, ipv6Title, ipv4Title, statusTitle)
	}

	for _, ep := range eps {
		if ep.Identity == nil {
			listEndpoint(w, ep, "<no label id>", "")
		} else {
			id := fmt.Sprintf("%d", ep.Identity.ID)

			if len(ep.Identity.Labels) == 0 {
				listEndpoint(w, ep, id, "no labels")
			} else {
				first := true
				for _, lbl := range ep.Identity.Labels {
					if first {
						listEndpoint(w, ep, id, lbl)
						first = false
					} else {
						fmt.Fprintf(w, "\t\t%s\t\t\t\t\n", lbl)
					}
				}
			}
		}

	}
	w.Flush()
}
