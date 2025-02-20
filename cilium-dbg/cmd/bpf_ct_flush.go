// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/cilium/stream"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/ctmap"
)

// bpfCtFlushCmd represents the bpf_ct_flush command
var bpfCtFlushCmd = &cobra.Command{
	Use:    "flush ( <endpoint identifier> | global )",
	Short:  "Flush all connection tracking entries",
	PreRun: requireEndpointIDorGlobal,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf ct flush")
		flushCt(args[0])
	},
}

func init() {
	BPFCtCmd.AddCommand(bpfCtFlushCmd)
}

type dummyEndpoint struct {
	ID int
}

func (d dummyEndpoint) GetID() uint64 {
	return uint64(d.ID)
}

func flushCt(eID string) {
	var maps []*ctmap.Map
	if eID == "global" {
		ipv4, ipv6 := getIpEnableStatuses()
		maps = ctmap.GlobalMaps(ipv4, ipv6)
	} else {
		id, _ := strconv.Atoi(eID)
		maps = ctmap.LocalMaps(&dummyEndpoint{ID: id}, true, true)
	}

	observable4, next4, complete4 := stream.Multicast[ctmap.GCEvent]()
	observable6, next6, complete6 := stream.Multicast[ctmap.GCEvent]()
	observable4.Observe(context.Background(), ctmap.NatMapNext4, func(error) {})
	observable6.Observe(context.Background(), ctmap.NatMapNext6, func(error) {})

	for _, m := range maps {
		path, err := ctmap.OpenCTMap(m)
		if err != nil {
			if os.IsNotExist(err) {
				msg := "Unable to open %s: %s."
				if eID != "global" {
					msg = "Unable to open %s: %s: please try using \"cilium bpf ct flush global\"."
				}
				fmt.Fprintf(os.Stderr, msg+" Skipping.\n", path, err)
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
