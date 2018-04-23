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
	"os"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/command"

	"fmt"
	"github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/spf13/cobra"
)

const (
	ipAddrTitle   = "IP ADDRESS"
	identityTitle = "IDENTITY"
)

var bpfIPCacheListCmd = &cobra.Command{
	Use:   "ipcache list",
	Short: "List endpoint IPs (local and remote) and their corresponding security identities",
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

		TablePrinter(ipAddrTitle, identityTitle, bpfIPCacheList)
	},
}

func init() {
	bpfCmd.AddCommand(bpfIPCacheListCmd)
	command.AddJSONOutput(bpfIPCacheListCmd)
}
