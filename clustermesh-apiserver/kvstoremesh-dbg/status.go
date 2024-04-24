// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dbg

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/kvstoremesh/client/cluster"
	ciliumdbg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/command"
)

var Status = func() *cobra.Command {
	var verbose bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Display status of remote clusters",
		Run:   func(cmd *cobra.Command, args []string) { status(cmd.Context(), cmd.OutOrStdout(), verbose) },
	}

	RootCmd.AddCommand(cmd)
	command.AddOutputOption(cmd)

	cmd.Flags().BoolVar(&verbose, "verbose", false, "Output verbose status information for ready clusters as well")

	return cmd
}()

func status(ctx context.Context, writer io.Writer, verbose bool) {
	params := cluster.NewGetClusterParams().WithContext(ctx)
	resp, err := client.Cluster.GetCluster(params)
	if err != nil {
		fmt.Printf("Failed to retrieve status information: %s\n", clientErrorHint(err))
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

	fmt.Fprintf(writer, "KVStoreMesh:\t%d/%d clusters ready\n",
		ciliumdbg.NumReadyClusters(clusters), len(clusters))
	ciliumdbg.FormatStatusResponseRemoteClusters(writer, clusters, verbosity)
}
