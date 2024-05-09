// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/go-openapi/strfmt"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/operator/client"
	"github.com/cilium/cilium/api/v1/operator/client/cluster"
	"github.com/cilium/cilium/operator/api"
	ciliumdbg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/command"
)

// StatusCmd represents the status command for the operator.
var StatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Display status of operator",
}

var StatusClusterMesh = func() *cobra.Command {
	var host string
	var verbose bool

	cmd := &cobra.Command{
		Use:   "clustermesh",
		Short: "Display status of remote clusters",
		Run:   func(cmd *cobra.Command, args []string) { status(cmd.Context(), host, cmd.OutOrStdout(), verbose) },

		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)
			cmd.SetContext(ctx)
		},
	}

	StatusCmd.AddCommand(cmd)
	command.AddOutputOption(cmd)

	cmd.Flags().StringVarP(&host, "server-address", "s", api.OperatorAPIServeAddrDefault, "Address of the operator API server")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Output verbose status information for ready clusters as well")

	return cmd
}()

func status(ctx context.Context, host string, writer io.Writer, verbose bool) {
	cfg := client.DefaultTransportConfig().WithHost(host)
	cl := client.NewHTTPClientWithConfig(strfmt.Default, cfg)

	params := cluster.NewGetClusterParams().WithContext(ctx)
	resp, err := cl.Cluster.GetCluster(params)
	if err != nil {
		fmt.Printf("Failed to retrieve status information: %s\n", err)
		os.Exit(1)
	}

	if command.OutputOption() {
		if err := command.PrintOutput(resp.Payload); err != nil {
			fmt.Printf("Failed to output status information: %s\n", err)
			os.Exit(1)
		}
		return
	}

	clusters := resp.GetPayload()

	verbosity := ciliumdbg.RemoteClustersStatusBrief
	if verbose {
		verbosity = ciliumdbg.RemoteClustersStatusVerbose
	}

	fmt.Fprintf(writer, "ClusterMesh:\t%d/%d clusters ready\n",
		ciliumdbg.NumReadyClusters(clusters), len(clusters))
	ciliumdbg.FormatStatusResponseRemoteClusters(writer, clusters, verbosity)
}
