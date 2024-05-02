// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/kvstore"
)

var troubleshootClusterMeshCmd = func() *cobra.Command {
	var cfg string
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "clustermesh [clusters...]",
		Short: "Troubleshoot connectivity towards remote clusters",
		Run: func(cmd *cobra.Command, args []string) {
			TroubleshootClusterMesh(
				cmd.Context(), cmd.OutOrStdout(),
				kvstore.DefaultEtcdDbgDialer{},
				cfg, timeout, args...)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&cfg, "clustermesh-config", "/var/lib/cilium/clustermesh/", "Path to the ClusterMesh configuration directory")
	flags.DurationVar(&timeout, "timeout", 5*time.Second, "Timeout when checking connectivity to a given remote cluster")

	return cmd
}()

func init() {
	TroubleshootCmd.AddCommand(troubleshootClusterMeshCmd)
}

func TroubleshootClusterMesh(
	ctx context.Context, stdout io.Writer, dialer kvstore.EtcdDbgDialer,
	cfgdir string, timeout time.Duration, clusters ...string,
) {
	cfgs, err := clustermesh.ConfigFiles(cfgdir)
	if err != nil {
		fmt.Fprintf(stdout, "Unable to retrieve remote cluster configurations: %s\n", err)
		fmt.Fprintf(stdout, "Is %q the correct configuration directory?\n", cfgdir)
		os.Exit(1)
	}

	fmt.Fprintf(stdout, "Found %d remote cluster configurations\n", len(cfgs))

	if len(clusters) == 0 {
		clusters = maps.Keys(cfgs)
	} else {
		fmt.Fprintf(stdout, "Troubleshooting filtered subset of clusters: %s\n", strings.Join(clusters, ", "))
	}

	// Sort the clusters by name to ensure consistent ordering.
	slices.Sort(clusters)

	for _, cluster := range clusters {
		fmt.Fprintf(stdout, "\nRemote cluster %q:\n", cluster)

		cfg, ok := cfgs[cluster]
		if !ok {
			fmt.Fprintln(stdout, "❌ Configuration not found")
			continue
		}

		cctx, cancel := context.WithTimeout(ctx, timeout)
		kvstore.EtcdDbg(cctx, cfg, dialer, stdout)
		cancel()
	}
}
