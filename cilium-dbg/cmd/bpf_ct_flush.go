// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/cilium/stream"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/ctmap"
)

// bpfCtFlushCmd represents the bpf_ct_flush command
var bpfCtFlushCmd = &cobra.Command{
	Use:   "flush global",
	Short: "Flush all connection tracking entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf ct flush")
		flushCt()
	},
}

func init() {
	BPFCtCmd.AddCommand(bpfCtFlushCmd)
}

func flushCt() {
	ipv4, ipv6 := getIpEnableStatuses()
	maps := ctmap.GlobalMaps(ipv4, ipv6)

	observable4, next4, complete4 := stream.Multicast[ctmap.GCEvent]()
	observable6, next6, complete6 := stream.Multicast[ctmap.GCEvent]()
	observable4.Observe(context.Background(), ctmap.NatMapNext4, func(error) {})
	observable6.Observe(context.Background(), ctmap.NatMapNext6, func(error) {})

	for _, m := range maps {
		path, err := ctmap.OpenCTMap(m)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Unable to open %s: %s. Skipping.\n", path, err)
				continue
			}
			Fatalf("Unable to open %s: %s", path, err)
		}
		defer m.Close()
		entries := m.Flush(next4, next6)
		fmt.Printf("Flushed %d entries from %s\n", entries, path)
	}

	complete4(nil)
	complete6(nil)
}
