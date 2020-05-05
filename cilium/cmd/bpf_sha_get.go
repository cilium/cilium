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
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"

	"github.com/spf13/cobra"
)

var bpfShaGetCmd = &cobra.Command{
	Use:     "get <sha>",
	Aliases: []string{"describe"},
	Short:   "Get datapath SHA header",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf sha get")
		if len(args) == 0 {
			cmd.Help()
		} else {
			dumpSha(args[0])
		}
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
		regex, err := regexp.Compile("// JSON_OUTPUT: (?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)")
		if err != nil {
			Fatalf("Error preparing regex for parsing JSON: %s\n", err)
		}

		jsonEncStr := regex.FindString(fmt.Sprintf("%s", text))
		if jsonEncStr == "" {
			Fatalf("No JSON embedded in the file.")
		}

		jsonStr, err := base64.StdEncoding.DecodeString(strings.Replace(jsonEncStr, "// JSON_OUTPUT: ", "", -1))
		if err != nil {
			Fatalf("Error while decoding JSON encoded as base64 string: %s", err)
		}

		if err := command.PrintOutput(jsonStr); err != nil {
			Fatalf("error printing output in JSON: %s\n", err)
		}
		return
	}

	fmt.Printf("%s", text)
}
