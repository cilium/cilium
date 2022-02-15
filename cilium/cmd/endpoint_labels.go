// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labels/model"
	"github.com/cilium/cilium/pkg/logging/logfields"
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
