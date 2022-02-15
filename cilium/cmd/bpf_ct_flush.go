// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"strconv"

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
	bpfCtCmd.AddCommand(bpfCtFlushCmd)
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
		maps = ctmap.GlobalMaps(true, getIpv6EnableStatus())
	} else {
		id, _ := strconv.Atoi(eID)
		maps = ctmap.LocalMaps(&dummyEndpoint{ID: id}, true, true)
	}
	for _, m := range maps {
		path, err := m.Path()
		if err == nil {
			err = m.Open()
		}
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
		entries := m.Flush()
		fmt.Printf("Flushed %d entries from %s\n", entries, path)
	}
}
