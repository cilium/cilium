// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	ipapi "github.com/cilium/cilium/api/v1/client/policy"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
	pkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/command"
	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
)

var (
	ipQueryLabels []string
)

var ipGetCmd = &cobra.Command{
	Use:   "get ( <cidr> |-l <identity labels> )",
	Short: "Display IP Cache information",
	Run: func(cmd *cobra.Command, args []string) {
		if len(ipQueryLabels) > 0 && len(args) > 0 {
			Usagef(cmd, "Cannot provide both cidr and labels arguments concurrently")
		}

		if len(ipQueryLabels) > 0 {
			lbls := labels.NewLabelsFromModel(ipQueryLabels).GetModel()
			if len(lbls) <= 0 {
				Fatalf("Labels cannot be empty %v", ipQueryLabels)
			}
			displayByLabels(lbls)
		} else {
			if len(args) < 1 || args[0] == "" {
				Usagef(cmd, "Missing cidr argument")
			}
			if _, _, err := net.ParseCIDR(args[0]); err != nil {
				Fatalf("Unable to parse CIDR %q: %v", args[0], err)
			}
			params := ipapi.NewGetIPParams().WithTimeout(api.ClientTimeout).WithCidr(&args[0])
			ipcache, err := client.Policy.GetIP(params)
			if err != nil {
				Fatalf("Cannot get ipcache entries. err: %s", pkg.Hint(err))
			}
			im := ipcachetypes.IPListEntrySlice(ipcache.Payload)
			sort.Slice(im, im.Less)
			printIPcacheEntries(ipcache.Payload)
		}
	},
}

func init() {
	IPCmd.AddCommand(ipGetCmd)
	command.AddOutputOption(ipGetCmd)
	flags := ipGetCmd.Flags()
	flags.StringSliceVarP(&ipQueryLabels, "labels", "l", []string{}, "list of labels")
	flags.BoolVarP(&verbose, "verbose", "v", false, "Print all fields of ipcache")
	vp.BindPFlags(flags)
}

func displayByLabels(lbls models.Labels) {
	params := ipapi.NewGetIPParams().WithLabels(lbls).WithTimeout(api.ClientTimeout)
	fmt.Printf("===========================\n")
	fmt.Printf("Labels:\n")
	for _, label := range lbls {
		fmt.Printf("    %s\n", label)
	}
	fmt.Printf("===========================\n")
	result, err := client.Policy.GetIP(params)
	if err != nil {
		Fatalf("Cannot get ipcache entries. err: %s", pkg.Hint(err))
	}
	im := ipcachetypes.IPListEntrySlice(result.Payload)
	sort.Slice(im, im.Less)
	if verbose {
		printIPcacheEntries(result.Payload)
	} else {
		printIPcacheEntriesBrief(result.Payload)
	}
}

func printIPcacheEntriesBrief(entries []*models.IPListEntry) {
	if command.OutputOption() {
		if err := command.PrintOutput(entries); err != nil {
			Fatalf("Unable to provide %s output: %s", command.OutputOptionString(), err)
		}
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	fmt.Fprintf(w, "IP\tHOST\tIDENTITY\tPOD\tNAMESPACE\n")
	for _, entry := range entries {
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n", *entry.Cidr, entry.HostIP, *entry.Identity, entry.Metadata.Name, entry.Metadata.Namespace)
	}
	w.Flush()
}
