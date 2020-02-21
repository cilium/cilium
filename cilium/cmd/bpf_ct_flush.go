// Copyright 2017-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/maps/ctmap"

	"github.com/spf13/cobra"
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
	pm := probes.NewProbeManager()
	supportedMapTypes := pm.GetMapTypes()
	if eID == "global" {
		maps = ctmap.GlobalMaps(true, true, supportedMapTypes.HaveLruHashMapType)
	} else {
		id, _ := strconv.Atoi(eID)
		maps = ctmap.LocalMaps(&dummyEndpoint{ID: id}, true, true,
			supportedMapTypes.HaveLruHashMapType)
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
