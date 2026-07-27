// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dbg

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/kvstore"
)

var Troubleshoot = func() *cobra.Command {
	var etcdcfg string
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "troubleshoot",
		Short: "Troubleshoot connectivity towards the local etcd kvstore",
		Run: func(cmd *cobra.Command, args []string) {
			stdout := cmd.OutOrStdout()

			fmt.Fprintf(stdout, "Local etcd kvstore:\n")
			cctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			kvstore.EtcdDbg(cctx, etcdcfg, kvstore.DefaultEtcdDbgDialer{}, stdout)
			cancel()
		},
	}

	RootCmd.AddCommand(cmd)

	flags := cmd.Flags()
	flags.StringVar(&etcdcfg, "etcd-config", "/var/lib/cilium/etcd-config.yaml", "Path to the etcd configuration")
	flags.DurationVar(&timeout, "timeout", 5*time.Second, "Timeout when checking connectivity to the etcd kvstore")

	return cmd
}()
