// Copyright 2018 Authors of Cilium
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

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/ipcache"

	"github.com/spf13/cobra"
)

const (
	ipAddrTitle          = "IP PREFIX/ADDRESS"
	identityTitle        = "IDENTITY"
	ipCacheListUsage     = "List endpoint IPs (local and remote) and their corresponding security identities.\n" + kernelVersionWarning
	kernelVersionWarning = `
Note that for Linux kernel versions between 4.11 and 4.15 inclusive, the native
LPM map type used for implementing the IPCache does not provide the ability to
walk / dump the entries, so on these kernel versions this tool will never
return any entries, even if entries exist in the map. You may instead run:
    cilium map get cilium_ipcache
`
)

var bpfIPCacheListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List endpoint IPs (local and remote) and their corresponding security identities",
	Long:    ipCacheListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf ipcache list")

		bpfIPCacheList := make(map[string][]string)
		if err := ipcache.IPCache.Dump(bpfIPCacheList); err != nil {
			fmt.Fprintf(os.Stderr, "error dumping contents of map: %s\n", err)
			os.Exit(1)
		}

		if command.OutputJSON() {
			if err := command.PrintOutput(bpfIPCacheList); err != nil {
				fmt.Fprintf(os.Stderr, "error getting output of map in JSON: %s\n", err)
				os.Exit(1)
			}
			return
		}

		if len(bpfIPCacheList) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n%v\n", kernelVersionWarning)
		} else {
			TablePrinter(ipAddrTitle, identityTitle, bpfIPCacheList)
		}
	},
}

func init() {
	bpfIPCacheCmd.AddCommand(bpfIPCacheListCmd)
	command.AddJSONOutput(bpfIPCacheListCmd)
}
