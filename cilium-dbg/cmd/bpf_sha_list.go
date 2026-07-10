// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/defaults"
)

const (
	shaTitle       = "Datapath SHA"
	endpointsTitle = "Endpoint(s)"
)

var (
	stateDir     = filepath.Join(defaults.RuntimePath, defaults.StateDir)
	templatesDir = filepath.Join(stateDir, defaults.TemplatesDir)

	bpfTemplateListCmd = &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List BPF template objects.",
		Run: func(cmd *cobra.Command, args []string) {
			common.RequireRootPrivilege("cilium bpf sha list")
			dumpShaList()
		},
	}
)

func init() {
	BPFTemplateCmd.AddCommand(bpfTemplateListCmd)
	command.AddOutputOption(bpfTemplateListCmd)
}

func isEndpointID(name string) bool {
	_, err := strconv.Atoi(name)
	return err == nil
}

// getTemplateSHA returns the SHA that should be reported to the user for
// the specified endpoint ID.
func getTemplateSHA(epID string) string {
	contents, err := os.ReadFile(filepath.Join(stateDir, epID, defaults.TemplateIDPath))
	if err != nil {
		return fmt.Sprintf("<missing %s>", defaults.TemplateIDPath)
	}

	templateID := string(bytes.TrimSpace(contents))
	if _, err := os.Stat(filepath.Join(templatesDir, templateID)); err != nil {
		return "<template path invalid>"
	}

	return templateID
}

func dumpShaList() {
	bpfTemplateList := make(map[string][]string)

	// Find all templates
	templateDirs, err := os.ReadDir(templatesDir)
	if err != nil {
		Fatalf("failed to list template directory: %s\n", err)
	}
	for _, d := range templateDirs {
		bpfTemplateList[d.Name()] = []string{}
	}

	// Find all endpoint usage of the templates
	stateDirs, err := os.ReadDir(stateDir)
	if err != nil {
		Fatalf("failed to list state directory: %s\n", err)
	}
	for _, d := range stateDirs {
		if d.IsDir() && isEndpointID(d.Name()) {
			epID := d.Name()
			sha := getTemplateSHA(epID)
			bpfTemplateList[sha] = append(bpfTemplateList[sha], epID)
		}
	}

	if command.OutputOption() {
		if err := command.PrintOutput(bpfTemplateList); err != nil {
			Fatalf("error getting output of map in %s: %s\n", command.OutputOptionString(), err)
		}
		return
	}

	// Mark unused templates with a "-" in text output
	for sha, eps := range bpfTemplateList {
		if len(eps) == 0 {
			bpfTemplateList[sha] = []string{"-"}
		}
	}
	if len(bpfTemplateList) == 0 {
		fmt.Fprintf(os.Stderr, "No entries found.\n")
	} else {
		TablePrinter(shaTitle, endpointsTitle, bpfTemplateList)
	}
}
