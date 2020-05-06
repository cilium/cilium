// Copyright 2019 Authors of Cilium
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

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/nat"

	"github.com/spf13/cobra"
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
	ipv4, ipv6 := nat.GlobalMaps(true, true)

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
