// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dbg

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	ciliumdbg "github.com/cilium/cilium/cilium-dbg/cmd"
	"github.com/cilium/cilium/pkg/kvstore"
)

var Troubleshoot = func() *cobra.Command {
	var etcdcfg, cmcfg string
	var timeout time.Duration
	var local bool

	cmd := &cobra.Command{
		Use:   "troubleshoot [clusters...]",
		Short: "Troubleshoot connectivity towards the local etcd kvstore and remote clusters",
		Run: func(cmd *cobra.Command, args []string) {
			// KVStoreMesh runs in pod network, so we don't need any
			// special logic for k8s service to IP resolution.
			dialer := kvstore.DefaultEtcdDbgDialer{}
			stdout := cmd.OutOrStdout()

			if local {
				fmt.Fprintf(stdout, "Local etcd kvstore:\n")
				cctx, cancel := context.WithTimeout(cmd.Context(), timeout)
				kvstore.EtcdDbg(cctx, etcdcfg, dialer, stdout)
				fmt.Fprintf(stdout, "\n\n")
				cancel()
			}

			ciliumdbg.TroubleshootClusterMesh(cmd.Context(), stdout, dialer, cmcfg, timeout, args...)
		},
	}

	RootCmd.AddCommand(cmd)

	flags := cmd.Flags()
	flags.StringVar(&etcdcfg, "etcd-config", "/var/lib/cilium/etcd-config.yaml", "Path to the etcd configuration")
	flags.StringVar(&cmcfg, "clustermesh-config", "/var/lib/cilium/clustermesh/", "Path to the ClusterMesh configuration directory")
	flags.BoolVar(&local, "include-local", false, "Additionally troubleshoot connectivity to the local etcd instance")
	flags.DurationVar(&timeout, "timeout", 5*time.Second, "Timeout when checking connectivity to a given etcd kvstore")

	return cmd
}()
