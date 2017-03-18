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
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/labels"

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
		_, id, _ := endpoint.ValidateID(args[0])
		lo := &models.LabelConfigurationModifier{}
		addLabels := labels.ParseStringLabels(toAdd)
		if len(addLabels) != 0 {
			lo.Add = addLabels.GetModel()
		}

		deleteLabels := labels.ParseStringLabels(toDelete)
		if len(deleteLabels) != 0 {
			lo.Delete = deleteLabels.GetModel()
		}

		if len(addLabels) > 0 || len(deleteLabels) > 0 {
			if err := client.EndpointLabelsPut(id, lo); err != nil {
				Fatalf("Cannot modifying labels %s", err)
			}
		}

		if lbls, err := client.EndpointLabelsGet(id); err != nil {
			Fatalf("Cannot get endpoint labels: %s", err)
		} else {
			printEndpointLabels(labels.NewOplabelsFromModel(lbls))
		}
	},
}

func init() {
	endpointCmd.AddCommand(endpointLabelsCmd)
	endpointLabelsCmd.Flags().StringSliceVarP(&toAdd, "add", "a", []string{}, "Add/enable labels")
	endpointLabelsCmd.Flags().StringSliceVarP(&toDelete, "delete", "d", []string{}, "Delete/disable labels")
}

func printEndpointLabels(lbls *labels.OpLabels) {
	log.Debugf("All Labels %#v", *lbls)
	w := tabwriter.NewWriter(os.Stdout, 2, 0, 3, ' ', 0)

	for _, v := range lbls.Enabled() {
		text := common.Green("Enabled")
		fmt.Fprintf(w, "%s\t%s\n", v, text)
	}

	for _, v := range lbls.Disabled {
		text := common.Red("Disabled")
		fmt.Fprintf(w, "%s\t%s\n", v, text)
	}
	w.Flush()
}
