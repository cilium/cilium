// Copyright 2017 Authors of Cilium
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

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/ctmap"

	"github.com/spf13/cobra"
)

// bpfCtFlushCmd represents the bpf_ct_flush command
var bpfCtFlushCmd = &cobra.Command{
	Use:    "flush",
	Short:  "Flush all connection tracking entries",
	PreRun: requireEndpointIDorGlobal,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf ct flush")
		if args[0] == "global" {
			flushCtProto(ctmap.MapName6Global, "")
			flushCtProto(ctmap.MapName4Global, "")
		} else {
			flushCtProto(ctmap.MapName6, args[0])
			flushCtProto(ctmap.MapName4, args[0])
		}
	},
}

func init() {
	bpfCtCmd.AddCommand(bpfCtFlushCmd)
}

func flushCtProto(mapType, eID string) {
	file := bpf.MapPath(mapType + eID)
	m, err := bpf.OpenMap(file)
	if err != nil {
		if err == os.ErrNotExist {
			Fatalf("Unable to open %s: %s: please try using \"cilium bpf ct flush global\"", file, err)
		} else {
			Fatalf("Unable to open %s: %s", file, err)
		}
	}
	defer m.Close()
	entries := ctmap.Flush(m, mapType)
	fmt.Println("Flushed", entries, "entries from", mapType)
}
