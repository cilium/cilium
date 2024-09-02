// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/kvstore"
)

var troubleshootClusterMeshCmd = func() *cobra.Command {
	var cfg string
	var timeout time.Duration
	var disableDialer bool

	cmd := &cobra.Command{
		Use:   "clustermesh [clusters...]",
		Short: "Troubleshoot connectivity towards remote clusters",
		Run: func(cmd *cobra.Command, args []string) {
			local := getLocalClusterName(cmd.ErrOrStderr())
			TroubleshootClusterMesh(
				cmd.Context(), cmd.OutOrStdout(),
				newTroubleshootDialer(cmd.ErrOrStderr(), disableDialer),
				cfg, timeout, local, args...)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&cfg, "clustermesh-config", "/var/lib/cilium/clustermesh/", "Path to the ClusterMesh configuration directory")
	flags.DurationVar(&timeout, "timeout", 5*time.Second, "Timeout when checking connectivity to a given cluster")
	flags.BoolVar(&disableDialer, "without-service-resolution", false, "Disable k8s service to IP resolution through the k8s client")

	return cmd
}()

func init() {
	TroubleshootCmd.AddCommand(troubleshootClusterMeshCmd)
}

func TroubleshootClusterMesh(
	ctx context.Context, stdout io.Writer, dialer kvstore.EtcdDbgDialer,
	cfgdir string, timeout time.Duration, local string, clusters ...string,
) {
	cfgs, err := common.ConfigFiles(cfgdir)
	if err != nil {
		fmt.Fprintf(stdout, "Unable to retrieve cluster configurations: %s\n", err)
		fmt.Fprintf(stdout, "Is %q the correct configuration directory?\n", cfgdir)
		os.Exit(1)
	}

	fmt.Fprintf(stdout, "Found %d cluster configurations\n", len(cfgs))

	if len(clusters) == 0 {
		clusters = slices.Collect(maps.Keys(cfgs))
	} else {
		fmt.Fprintf(stdout, "Troubleshooting filtered subset of clusters: %s\n", strings.Join(clusters, ", "))
	}

	// Sort the clusters by name to ensure consistent ordering.
	slices.Sort(clusters)

	for _, cluster := range clusters {
		fmt.Fprintf(stdout, "\nCluster %q:\n", cluster)
		if cluster == local {
			fmt.Fprintln(stdout, "ℹ️  This entry corresponds to the local cluster")
		}

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

func getLocalClusterName(w io.Writer) string {
	cfg, err := client.ConfigGet()
	if err != nil || cfg.Status == nil {
		fmt.Fprintln(w, "⚠️ Could not connect to the Cilium's API and retrieve the local cluster name")
		return ""
	}

	name, _ := cfg.Status.DaemonConfigurationMap["ClusterName"].(string)
	return name
}
