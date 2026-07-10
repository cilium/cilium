// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import "github.com/spf13/cobra"

// BpfMcastCmd represents the bpf command
var BpfMcastCmd = &cobra.Command{
	Use:     "multicast",
	Aliases: []string{"mcast"},
	Short:   "Manage multicast BPF programs",
}

func init() {
	BPFCmd.AddCommand(BpfMcastCmd)
	BpfMcastCmd.AddCommand(BpfMcastGroupCmd)
	BpfMcastCmd.AddCommand(BpfMcastSubscriberCmd)
}
