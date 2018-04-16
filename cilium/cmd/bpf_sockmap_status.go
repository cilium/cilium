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
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"

	"github.com/spf13/cobra"
)

var bpfSockmapStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Report sockmap status (enabled|disabled|unsupported)",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf sockmap status")
		if len(args) == 0 {
			isEnabled, _ := bpf.StatusSockopsProgram()
			if isEnabled == true {
				fmt.Printf("Status: Enabled\n")
			} else {
				fmt.Printf("Status: Disabled\n")
			}
		} else {
			if args[0] == "enable" {
				err := bpf.AttachSockopsProgram()
				if err == nil {
					fmt.Printf("Enabled\n")
				}
			} else if args[0] == "disable" {
				err := bpf.DetachSockopsProgram()
				if err == nil {
					fmt.Printf("Disabled\n")
				}
			} else {
				fmt.Printf("Unknown\n")
			}
		}
	},
}

func init() {
	bpfSockmapCmd.AddCommand(bpfSockmapStatusCmd)
	command.AddJSONOutput(bpfSockmapStatusCmd)
}
