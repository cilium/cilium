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

	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labels/model"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/spf13/cobra"
)

var (
	toAdd    []string
	toDelete []string
)

// endpointLabelsCmd represents the endpoint_labels command
var endpointLabelsCmd = &cobra.Command{
	Use:    "labels",
	Short:  "Manage label configuration of endpoint",
	PreRun: requireEndpointID,
	Run: func(cmd *cobra.Command, args []string) {
		_, id, _ := endpointid.Parse(args[0])
		addLabels := labels.NewLabelsFromModel(toAdd).GetModel()

		deleteLabels := labels.NewLabelsFromModel(toDelete).GetModel()

		if len(addLabels) > 0 || len(deleteLabels) > 0 {
			if err := client.EndpointLabelsPatch(id, addLabels, deleteLabels); err != nil {
				Fatalf("Cannot modifying labels %s", err)
			}
		}

		lbls, err := client.EndpointLabelsGet(id)
		switch {
		case err != nil:
			Fatalf("Cannot get endpoint labels: %s", err)
		case lbls == nil || lbls.Status == nil:
			Fatalf("Cannot get endpoint labels: empty response")
		default:
			printEndpointLabels(model.NewOplabelsFromModel(lbls.Status))
		}
	},
}

func init() {
	endpointCmd.AddCommand(endpointLabelsCmd)
	endpointLabelsCmd.Flags().StringSliceVarP(&toAdd, "add", "a", []string{}, "Add/enable labels")
	endpointLabelsCmd.Flags().StringSliceVarP(&toDelete, "delete", "d", []string{}, "Delete/disable labels")
}

// printEndpointLabels pretty prints labels with tabs
func printEndpointLabels(lbls *labels.OpLabels) {
	log.WithField(logfields.Labels, logfields.Repr(*lbls)).Debug("All Labels")
	w := tabwriter.NewWriter(os.Stdout, 2, 0, 3, ' ', 0)

	for _, v := range lbls.IdentityLabels() {
		fmt.Fprintf(w, "%s\t%s\n", v, "Enabled")
	}

	for _, v := range lbls.Disabled {
		fmt.Fprintf(w, "%s\t%s\n", v, "Disabled")
	}
	w.Flush()
}
