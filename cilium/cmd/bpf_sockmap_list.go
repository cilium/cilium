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
	"github.com/cilium/cilium/pkg/maps/sockmap"
	"github.com/spf13/cobra"
)

const (
	sockKey = "Sock Key"
)

var bpfSockmapListCmd = &cobra.Command{
	Use:   "list",
	Short: "List managed socket endpoints",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf sockmap list")

		bpfSockmapList := []string{}
		if err := sockmap.Sockmap.DumpKeys(&bpfSockmapList); err != nil {
			fmt.Fprintf(os.Stderr, "error dumping contents of map: %s\n", err)
			os.Exit(1)
		}

		ColumnPrinter(sockKey, bpfSockmapList)
	},
}

func init() {
	bpfSockmapCmd.AddCommand(bpfSockmapListCmd)
	command.AddJSONOutput(bpfSockmapListCmd)
}
