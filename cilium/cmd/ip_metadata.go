// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/ipcache"
)

var ipMetadataCmd = &cobra.Command{
	Use:   "metadata",
	Short: "List ID metadata information.",
	Run: func(cmd *cobra.Command, args []string) {
		listIDMetadata()
	},
}

func init() {
	ipCmd.AddCommand(ipMetadataCmd)
	command.AddJSONOutput(ipMetadataCmd)
	flags := ipMetadataCmd.Flags()
	viper.BindPFlags(flags)
}

func listIDMetadata() {
	identityMetadata := ipcache.GetIDMetadata()
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	for prefix, labels := range identityMetadata {
		fmt.Fprintf(w, "%s\t%s\n", prefix, labels.String())
	}
	w.Flush()
}
