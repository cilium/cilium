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
	"os"
	"path/filepath"
	"strconv"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/defaults"

	"github.com/spf13/cobra"
)

const (
	shaTitle       = "Datapath SHA"
	endpointsTitle = "Endpoint(s)"

	noSHA     = "<No template used>"
	brokenSHA = "<Template path invalid>"
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
	bpfTemplateCmd.AddCommand(bpfTemplateListCmd)
	command.AddJSONOutput(bpfTemplateListCmd)
}

func isEndpointID(name string) bool {
	_, err := strconv.Atoi(name)
	return err == nil
}

// getTemplateSHA returns the SHA that should be reported to the user for
// the specified endpoint ID.
func getTemplateSHA(epID string) string {
	// Get symlink from endpointDir
	templateSymlink := filepath.Join(stateDir, epID, defaults.TemplatePath)
	f, err := os.Lstat(templateSymlink)
	if err != nil {
		return noSHA
	}
	if f.Mode()&os.ModeSymlink == 0 {
		return brokenSHA
	}

	template, err := os.Readlink(templateSymlink)
	if err != nil {
		return brokenSHA
	}
	if _, err = os.Stat(template); err != nil {
		return brokenSHA
	}
	return filepath.Base(filepath.Dir(template))
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

	if command.OutputJSON() {
		if err := command.PrintOutput(bpfTemplateList); err != nil {
			Fatalf("error getting output of map in JSON: %s\n", err)
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
