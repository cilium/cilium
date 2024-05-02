// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/kvstore"
)

var troubleshootKVStoreCmd = func() *cobra.Command {
	var cfg string
	var timeout time.Duration
	var disableDialer bool

	cmd := &cobra.Command{
		Use:   "kvstore",
		Short: "Troubleshoot connectivity towards the etcd kvstore",
		Run: func(cmd *cobra.Command, args []string) {
			stdout := cmd.OutOrStdout()

			// Check if the etcd configuration file does not exist, to provide a more
			// helpful error in case this is expected as Cilium is running in CRD mode.
			if _, err := os.Stat(cfg); errors.Is(err, os.ErrNotExist) {
				fmt.Fprintf(stdout, "Unable to read etcd configuration: %s\n", cfg)
				fmt.Fprintf(stdout, "This is expected when Cilium is running in CRD mode\n")
				return
			}

			dialer := newTroubleshootDialer(cmd.ErrOrStderr(), disableDialer)

			cctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			kvstore.EtcdDbg(cctx, cfg, dialer, stdout)
			cancel()
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&cfg, "etcd-config", "/var/lib/etcd-config/etcd.config", "Path to the etcd configuration")
	flags.DurationVar(&timeout, "timeout", 5*time.Second, "Timeout when checking connectivity to the kvstore")
	flags.BoolVar(&disableDialer, "without-service-resolution", false, "Disable k8s service to IP resolution through the k8s client")

	return cmd
}()

func init() {
	TroubleshootCmd.AddCommand(troubleshootKVStoreCmd)
}
