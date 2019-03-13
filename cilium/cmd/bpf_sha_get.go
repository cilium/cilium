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
	"io/ioutil"
	"path/filepath"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/command"

	"github.com/spf13/cobra"
)

var bpfShaGetCmd = &cobra.Command{
	Use:     "get <sha>",
	Aliases: []string{"describe"},
	Short:   "Get datapath SHA header",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf sha get")
		dumpSha(args[0])
	},
}

func init() {
	bpfTemplateCmd.AddCommand(bpfShaGetCmd)
	command.AddJSONOutput(bpfShaGetCmd)
}

func dumpSha(sha string) {
	headerPath := filepath.Join(templatesDir, sha, common.CHeaderFileName)
	text, err := ioutil.ReadFile(headerPath)
	if err != nil {
		Fatalf("Failed to describe SHA: %s", err)
	}

	if command.OutputJSON() {
		if err := command.PrintOutput(fmt.Sprintf("%s", text)); err != nil {
			Fatalf("error printing output in JSON: %s\n", err)
		}
		return
	}

	fmt.Printf("%s", text)
}
