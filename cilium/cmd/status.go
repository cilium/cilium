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

	"github.com/cilium/cilium/api/v1/models"
	pkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/command"

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
var allControllers bool

func init() {
	rootCmd.AddCommand(statusCmd)
	statusCmd.Flags().BoolVar(&allControllers, "all-controllers", false, "Show all controllers, not just failing")
	command.AddJSONOutput(statusCmd)
}

func statusDaemon() {
	if resp, err := client.Daemon.GetHealthz(nil); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", pkg.Hint(err))
		os.Exit(1)
	} else if command.OutputJSON() {
		if err := command.PrintOutput(resp.Payload); err != nil {
			os.Exit(1)
		}
		return
	} else {
		sr := resp.Payload
		w := tabwriter.NewWriter(os.Stdout, 2, 0, 3, ' ', 0)
		pkg.FormatStatusResponse(w, sr, allControllers)
		w.Flush()

		if sr.Cilium != nil && sr.Cilium.State != models.StatusStateOk {
			os.Exit(1)
		} else {
			os.Exit(0)
		}
	}
}
