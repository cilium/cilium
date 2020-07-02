// Copyright 2020 Authors of Cilium
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
	"text/tabwriter"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"

	"github.com/spf13/cobra"
)

var kernelCheckCmd = &cobra.Command{
	Use:   "kernel-check",
	Short: "Checks whether the system has required kernel capabilities",
	Run: func(cmd *cobra.Command, args []string) {
		kernelCheck()
	},
}

// KernelParamSupport contains fields required for dumping JSON output
type KernelParamSupport struct {
	Feature     probes.KernelParam
	Supported   bool
	Required    bool
	Description string
}

func kernelCheck() {
	probeManager := probes.NewProbeManager()
	listParams := []KernelParamSupport{}
	requiredParams := probeManager.GetRequiredConfig()
	for f, s := range requiredParams {
		listParams = append(listParams, KernelParamSupport{
			Feature:     f,
			Supported:   s.Enabled,
			Required:    true,
			Description: s.Description,
		})
	}
	optionalParams := probeManager.GetOptionalConfig()
	for f, s := range optionalParams {
		listParams = append(listParams, KernelParamSupport{
			Feature:     f,
			Supported:   s.Enabled,
			Required:    false,
			Description: s.Description,
		})
	}
	if command.OutputJSON() {
		if err := command.PrintOutput(listParams); err != nil {
			Fatalf("Unable to generate JSON output: %s", err)
			os.Exit(1)
		}
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 30, 8, 0, ' ', 0)
	fmt.Fprintln(w, "FEATURE\tSUPPORTED\tREQUIRED\tDESCRIPTION")
	for _, p := range listParams {
		fmt.Fprintf(w, "%s\t%t\t%t\t%s\n", p.Feature, p.Supported, p.Required, p.Description)
	}
	w.Flush()
}

func init() {
	rootCmd.AddCommand(kernelCheckCmd)
	command.AddJSONOutput(kernelCheckCmd)
}
