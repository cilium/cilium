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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/cilium/cilium/api/v1/health/models"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	probe   bool
	verbose bool
)

func formatConnectivityStatus(w io.Writer, cs *models.ConnectivityStatus, path, indent string) {
	status := cs.Status
	if status == "" {
		latency := time.Duration(cs.Latency)
		status = fmt.Sprintf("OK, RTT=%s", latency)
	}
	fmt.Fprintf(w, "%s%s:\t%s\n", indent, path, status)
}

func formatPathStatus(w io.Writer, name string, cp *models.PathStatus, indent string) {
	if cp == nil {
		if verbose {
			fmt.Fprintf(w, "%s%s connectivity:\tnil\n", indent, name)
		}
		return
	}
	fmt.Fprintf(w, "%s%s connectivity to %s:\n", indent, name, cp.IP)
	indent = fmt.Sprintf("%s  ", indent)

	statuses := map[string]*models.ConnectivityStatus{
		"ICMP":        cp.Icmp,
		"HTTP via L3": cp.HTTP,
	}
	for name, status := range statuses {
		if status != nil {
			formatConnectivityStatus(w, status, name, indent)
		}
	}
}

// statusGetCmd represents the status command
var statusGetCmd = &cobra.Command{
	Use:     "status",
	Aliases: []string{"connectivity"},
	Short:   "Display cilium connectivity to other nodes",
	Run: func(cmd *cobra.Command, args []string) {
		var sr *models.HealthStatusResponse

		if probe {
			result, err := client.Connectivity.PutStatusProbe(nil)
			if err != nil {
				Fatalf("Cannot get status/probe: %s\n", err)
			}
			sr = result.Payload
		} else {
			result, err := client.Connectivity.GetStatus(nil)
			if err != nil {
				Fatalf("Cannot get status: %s\n", err)
			}
			sr = result.Payload
		}

		if msg, err := json.MarshalIndent(sr, "", "  "); err != nil {
			Fatalf("Cannot marshal response %s", err.Error())
		} else if viper.GetBool("json") {
			w := tabwriter.NewWriter(os.Stdout, 2, 0, 3, ' ', 0)
			fmt.Fprintf(w, "%s\n", msg)
			w.Flush()
		} else {
			w := tabwriter.NewWriter(os.Stdout, 2, 0, 3, ' ', 0)
			fmt.Fprintf(w, "Probe time:\t%s\n", sr.Timestamp)
			fmt.Fprintf(w, "Nodes:\n")
			for _, node := range sr.Nodes {
				localStr := ""
				if sr.Local != nil && node.Name == sr.Local.Name {
					localStr = " (localhost)"
				}
				fmt.Fprintf(w, "  %s%s:\n", node.Name, localStr)
				formatPathStatus(w, "Host", node.Host.PrimaryAddress, "    ")
				if verbose && len(node.Host.SecondaryAddresses) > 0 {
					for _, addr := range node.Host.SecondaryAddresses {
						formatPathStatus(w, "Secondary", addr, "      ")
					}
				}
				formatPathStatus(w, "Endpoint", node.Endpoint, "    ")
			}
			w.Flush()
		}
	},
}

func init() {
	rootCmd.AddCommand(statusGetCmd)
	statusGetCmd.Flags().BoolVarP(&probe, "probe", "", false,
		"Synchronously probe connectivity status")
	statusGetCmd.Flags().BoolVarP(&verbose, "verbose", "", false,
		"Print the result verbosely")
}
