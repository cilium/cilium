// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/nat"
)

// bpfNatRetriesFlushCmd represents the bpf_nat_flush command
var bpfNatRetriesFlushCmd = &cobra.Command{
	Use:   "flush",
	Short: "Reset the NAT retries histogram",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf nat retries flush")
		flushRetries()
	},
}

func init() {
	BPFNatRetriesCmd.AddCommand(bpfNatRetriesFlushCmd)
}

func flushRetries() {
	ipv4, ipv6 := getIpEnableStatuses()
	ipv4Map, ipv6Map := nat.RetriesMaps(ipv4, ipv6, true)

	for _, m := range []nat.RetriesMap{ipv4Map, ipv6Map} {
		if m == nil {
			continue
		}
		path, err := m.Path()
		if err == nil {
			err = m.Open()
		}
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Unable to open %s: %s. Skipping.\n", path, err)
				continue
			}
			Fatalf("Unable to open %s: %s", path, err)
		}
		defer m.Close()

		if err = m.ClearAll(); err != nil {
			Fatalf("Error while clearing BPF map entries: %s", err)
		}
	}
}
