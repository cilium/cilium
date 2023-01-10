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

// bpfNatFlushCmd represents the bpf_nat_flush command
var bpfNatFlushCmd = &cobra.Command{
	Use:   "flush",
	Short: "Flush all NAT mapping entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf nat flush")
		flushNat()
	},
}

func init() {
	bpfNatCmd.AddCommand(bpfNatFlushCmd)
}

func flushNat() {
	ipv4, ipv6 := nat.GlobalMaps(true, getIpv6EnableStatus(), true)

	for _, m := range []*nat.Map{ipv4, ipv6} {
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
		entries := m.Flush()
		fmt.Printf("Flushed %d entries from %s\n", entries, path)
	}
}
