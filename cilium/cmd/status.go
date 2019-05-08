// Copyright 2017 Authors of Cilium
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

	"github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/api/v1/models"
	pkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/command"
	healthPkg "github.com/cilium/cilium/pkg/health/client"

	"github.com/spf13/cobra"
)

// statusCmd represents the daemon_status command
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Display status of daemon",
	Run: func(cmd *cobra.Command, args []string) {
		statusDaemon()
	},
}
var (
	allAddresses   bool
	allControllers bool
	allHealth      bool
	allNodes       bool
	allRedirects   bool
	brief          bool
	healthLines    = 10
)

func init() {
	rootCmd.AddCommand(statusCmd)
	statusCmd.Flags().BoolVar(&allAddresses, "all-addresses", false, "Show all allocated addresses, not just count")
	statusCmd.Flags().BoolVar(&allControllers, "all-controllers", false, "Show all controllers, not just failing")
	statusCmd.Flags().BoolVar(&allHealth, "all-health", false, "Show all health status, not just failing")
	statusCmd.Flags().BoolVar(&allNodes, "all-nodes", false, "Show all nodes, not just localhost")
	statusCmd.Flags().BoolVar(&allRedirects, "all-redirects", false, "Show all redirects")
	statusCmd.Flags().BoolVar(&brief, "brief", false, "Only print a one-line status message")
	statusCmd.Flags().BoolVar(&verbose, "verbose", false, "Equivalent to --all-addresses --all-controllers --all-nodes --all-health")
	command.AddJSONOutput(statusCmd)
}

func statusDaemon() {
	isUnhealthy := func(sr *models.StatusResponse) bool {
		if sr.Cilium != nil {
			state := sr.Cilium.State
			return state != models.StatusStateOk && state != models.StatusStateDisabled
		}

		return false
	}

	if verbose {
		allAddresses = true
		allControllers = true
		allHealth = true
		allNodes = true
		allRedirects = true
	}
	if allHealth {
		healthLines = 0
	}
	params := daemon.NewGetHealthzParams()
	params.SetBrief(&brief)
	if resp, err := client.Daemon.GetHealthz(params); err != nil {
		if brief {
			fmt.Fprintf(os.Stderr, "%s\n", "cilium: daemon unreachable")
		} else {
			fmt.Fprintf(os.Stderr, "%s\n", pkg.Hint(err))
		}
		os.Exit(1)
	} else if command.OutputJSON() {
		if err := command.PrintOutput(resp.Payload); err != nil {
			os.Exit(1)
		}
	} else if brief {
		sr := resp.Payload
		pkg.FormatStatusResponseBrief(os.Stdout, sr)
		if isUnhealthy(sr) {
			os.Exit(1)
		}
	} else {
		sr := resp.Payload
		w := tabwriter.NewWriter(os.Stdout, 2, 0, 3, ' ', 0)
		pkg.FormatStatusResponse(w, sr, allAddresses, allControllers, allNodes, allRedirects)
		w.Flush()

		if isUnhealthy(sr) {
			os.Exit(1)
		}

		healthPkg.GetAndFormatHealthStatus(w, true, allHealth, healthLines)
		w.Flush()
	}
}
