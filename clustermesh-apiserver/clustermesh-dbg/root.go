// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dbg

import (
	"context"
	"os"
	"os/signal"

	"github.com/spf13/cobra"
)

var RootCmd = func() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "clustermesh-dbg",
		Short: "CLI for interacting with ClusterMesh",

		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)
			cmd.SetContext(ctx)
		},
	}

	return cmd
}()
