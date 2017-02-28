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

	"github.com/spf13/cobra"
)

// statusCmd represents the daemon_status command
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Display stsatus of daemon",
	Run: func(cmd *cobra.Command, args []string) {
		statusDaemon(cmd, args)
	},
}

func init() {
	RootCmd.AddCommand(statusCmd)
}

func statusDaemon(cmd *cobra.Command, args []string) {
	if resp, err := client.Daemon.GetHealthz(nil); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Unable to reach out daemon: %s\n", err)
		os.Exit(1)
	} else {
		sr := resp.Payload
		w := tabwriter.NewWriter(os.Stdout, 2, 0, 3, ' ', 0)
		if sr.Kvstore != nil {
			fmt.Fprintf(w, "KVStore:\t%s\n", sr.Kvstore.State)
		}
		if sr.ContainerRuntime != nil {
			fmt.Fprintf(w, "ContainerRuntime:\t%s\n", sr.ContainerRuntime.State)
		}
		if sr.Kubernetes != nil {
			fmt.Fprintf(w, "Kubernetes:\t%s\n", sr.Kubernetes.State)
		}
		if sr.Cilium != nil {
			fmt.Fprintf(w, "Cilium:\t%s\n", sr.Cilium.State)
		}

		if sr.IPAM != nil {
			fmt.Printf("Allocated IPv4 addresses:\n")
			for _, ipv4 := range sr.IPAM.IPV4 {
				fmt.Printf(" %s\n", ipv4)

			}
			fmt.Printf("Allocated IPv6 addresses:\n")
			for _, ipv6 := range sr.IPAM.IPV6 {
				fmt.Printf(" %s\n", ipv6)
			}
		}

		w.Flush()

		if sr.Cilium != nil && sr.Cilium.State != models.StatusStateOk {
			os.Exit(1)
		} else {
			os.Exit(0)
		}
	}

}
