// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/cilium/statedb"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/api/v1/models"
	pkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/command"
	healthPkg "github.com/cilium/cilium/pkg/health/client"
	"github.com/cilium/cilium/pkg/health/defaults"
	"github.com/cilium/cilium/pkg/hive/health"
	"github.com/cilium/cilium/pkg/hive/health/types"
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
	statusDetails          pkg.StatusDetails
	allHealth              bool
	brief                  bool
	requireK8sConnectivity bool
	timeout                time.Duration
	healthLines            = 10
	allNodes               = false
)

func init() {
	RootCmd.AddCommand(statusCmd)
	statusCmd.Flags().BoolVar(&statusDetails.AllAddresses, "all-addresses", false, "Show all allocated addresses, not just count")
	statusCmd.Flags().BoolVar(&statusDetails.AllControllers, "all-controllers", false, "Show all controllers, not just failing")
	statusCmd.Flags().BoolVar(&statusDetails.AllNodes, "all-nodes", false, "Show all nodes, not just localhost")
	statusCmd.Flags().BoolVar(&statusDetails.AllRedirects, "all-redirects", false, "Show all redirects")
	statusCmd.Flags().BoolVar(&statusDetails.AllClusters, "all-clusters", false, "Show all clusters")
	statusCmd.Flags().BoolVar(&allHealth, "all-health", false, "Show all health status, not just failing")
	statusCmd.Flags().BoolVar(&brief, "brief", false, "Only print a one-line status message")
	statusCmd.Flags().BoolVar(&requireK8sConnectivity, "require-k8s-connectivity", true, "If true, when the cilium-agent cannot access the Kubernetes control plane, this status command returns a non-zero exit status.")
	statusCmd.Flags().BoolVar(&verbose, "verbose", false, "Equivalent to --all-addresses --all-controllers --all-nodes --all-redirects --all-clusters --all-health")
	statusCmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "Sets the timeout to use when querying for health")
	command.AddOutputOption(statusCmd)
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
		statusDetails = pkg.StatusAllDetails
		allHealth = true
	}
	if allHealth {
		healthLines = 0
	}

	if statusDetails.AllNodes {
		allNodes = true
		healthLines = 0
	}

	params := daemon.NewGetHealthzParamsWithTimeout(timeout)
	params.SetBrief(&brief)
	params.SetRequireK8sConnectivity(&requireK8sConnectivity)
	if resp, err := client.Daemon.GetHealthz(params); err != nil {
		if brief {
			fmt.Fprintf(os.Stderr, "%s\n", "cilium: daemon unreachable")
		} else {
			fmt.Fprintf(os.Stderr, "%s\n", pkg.Hint(err))
		}
		os.Exit(1)
	} else if command.OutputOption() {
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
		pkg.FormatStatusResponse(w, sr, statusDetails)

		if isUnhealthy(sr) {
			w.Flush()
			os.Exit(1)
		}

		healthEnabled := false
		for _, c := range sr.Controllers {
			if c.Name == defaults.HealthEPName {
				healthEnabled = true
				break
			}
		}
		if healthEnabled {
			table := newRemoteTable[types.Status]("health")
			iter, errChan := table.LowerBound(context.Background(), health.PrimaryIndex.Query("agent"))
			ss := statedb.Collect(iter)
			if err := <-errChan; err != nil {
				Fatalf("Failed while streaming remote health data table: %s", err)
			}

			healthPkg.GetAndFormatHealthStatus(w, allNodes, verbose, healthLines)
			fmt.Fprintf(w, "Modules Health:")
			healthPkg.GetAndFormatModulesHealth(w, ss, allHealth, "\t\t")
			fmt.Fprintln(w)
		} else {
			fmt.Fprint(w, "Cluster health:\t\tProbe disabled\n")
		}
		w.Flush()
	}
}
