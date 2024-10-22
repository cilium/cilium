// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"path/filepath"

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
	BPFTemplateCmd.AddCommand(bpfShaGetCmd)
	command.AddOutputOption(bpfShaGetCmd)
}

func dumpSha(sha string) {
	if command.OutputOption() {
		headerPath := filepath.Join(templatesDir, sha, common.EndpointStateFileName)
		state, err := os.ReadFile(headerPath)
		if err != nil {
			Fatalf("Failed to describe SHA: %s", err)
		}

		if err := command.PrintOutput(state); err != nil {
			Fatalf("error printing output in %s: %s\n", command.OutputOptionString(), err)
		}
		return
	}

	headerPath := filepath.Join(templatesDir, sha, common.CHeaderFileName)
	text, err := os.ReadFile(headerPath)
	if err != nil {
		Fatalf("Failed to describe SHA: %s", err)
	}

	fmt.Printf("%s", text)
}
