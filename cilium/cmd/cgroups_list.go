// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/models"
	pkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/command"
)

var cgroupsListNoHeaders bool

// cgroupsListCmd represents the cgroups_list command
var cgroupsListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "Display cgroup metadata maintained by Cilium",
	Run: func(cmd *cobra.Command, args []string) {
		listCgroups()
	},
}

func init() {
	cgroupsCmd.AddCommand(cgroupsListCmd)
	cgroupsListCmd.Flags().BoolVar(&cgroupsListNoHeaders, "no-headers", false, "Do not print headers")
	command.AddOutputOption(cgroupsListCmd)
}

func listCgroups() {
	resp, err := client.Daemon.GetCgroupDumpMetadata(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", pkg.Hint(err))
		os.Exit(1)
	}

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	printMetadata(w, resp.Payload)
}

func printMetadata(w *tabwriter.Writer, metadata *models.CgroupDumpMetadata) {
	if metadata == nil {
		fmt.Fprint(w, "Unable to retrieve cgroups metadata")
		w.Flush()
		os.Exit(1)
	}

	podMetas := metadata.PodMetadatas
	if command.OutputOption() {
		if err := command.PrintOutput(podMetas); err != nil {
			os.Exit(1)
		}
		return
	}

	const (
		podNameTitle      = "POD NAME"
		podNamespaceTitle = "POD NAMESPACE"
		cgroupIdsTitle    = "CGROUP IDS"
	)

	if !cgroupsListNoHeaders {
		fmt.Fprintf(w, "%s\t%s\t%s\t\n", podNameTitle, podNamespaceTitle, cgroupIdsTitle)
	}

	for _, pm := range podMetas {
		for i, container := range pm.Containers {
			if i == 0 {
				fmt.Fprintf(w, "%s\t%s\t%d\t\n", pm.Name, pm.Namespace, container.CgroupID)
			} else {
				fmt.Fprintf(w, "\t\t%d\t\n", container.CgroupID)
			}
		}
	}
	w.Flush()
}
