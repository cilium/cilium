// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/client/policy"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/command"
)

var fqdnGCCacheCmd = &cobra.Command{
	Use:   "gccache",
	Short: "Manage FQDN garbage collection cache",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var fqdnGCCacheListCmd = &cobra.Command{
	Use:   "list",
	Short: "List recently garbage-collected FQDNs",
	Run: func(cmd *cobra.Command, args []string) {
		listFQDNGCCache()
	},
}

func init() {
	fqdnGCCacheCmd.AddCommand(fqdnGCCacheListCmd)
	command.AddOutputOption(fqdnGCCacheListCmd)
}

func listFQDNGCCache() {
	params := policy.NewGetFqdnGccacheParams()

	result, err := client.Policy.GetFqdnGccache(params)
	if err != nil {
		Fatalf("Error: %s\n", err)
	}

	entries := result.Payload
	if len(entries) == 0 {
		fmt.Println("No garbage-collected FQDN entries found")
		return
	}

	if command.OutputOption() {
		if err := command.PrintOutput(entries); err != nil {
			Fatalf("Unable to provide %s output: %s", command.OutputOptionString(), err)
		}
		return
	}

	printGCCacheTable(entries)
}

func printGCCacheTable(entries []*models.FQDNGCCacheEntry) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	fmt.Fprintln(w, "FQDN\tGC Time\t")
	for _, entry := range entries {
		fmt.Fprintf(w, "%s\t%s\t\n",
			entry.Fqdn,
			entry.GarbageCollectionTime.String())
	}
	w.Flush()
}
