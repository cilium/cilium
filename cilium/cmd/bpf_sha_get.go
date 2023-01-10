// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
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
	command.AddOutputOption(bpfShaGetCmd)
}

func dumpSha(sha string) {
	headerPath := filepath.Join(templatesDir, sha, common.CHeaderFileName)
	text, err := os.ReadFile(headerPath)
	if err != nil {
		Fatalf("Failed to describe SHA: %s", err)
	}

	if command.OutputOption() {
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
			Fatalf("error printing output in %s: %s\n", command.OutputOptionString(), err)
		}
		return
	}

	fmt.Printf("%s", text)
}
