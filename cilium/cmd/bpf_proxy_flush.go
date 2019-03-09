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

	"github.com/cilium/cilium/common"

	"github.com/spf13/cobra"
)

// bpfProxyFlushCmd represents the bpf_proxy_flush command
var bpfProxyFlushCmd = &cobra.Command{
	Use:    "flush",
	Short:  "Flush all proxy entries (deprecated)",
	PreRun: requireEndpointIDorGlobal,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf proxy flush")
		entries := 0
		fmt.Printf("Flushed %d entries\n", entries)
	},
}

func init() {
	bpfProxyCmd.AddCommand(bpfProxyFlushCmd)
}
