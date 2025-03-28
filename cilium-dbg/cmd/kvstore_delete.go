// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/logging"
)

var kvstoreDeleteCmd = &cobra.Command{
	Use:     "delete [options] <key>",
	Short:   "Delete a key",
	Example: "cilium kvstore delete --recursive foo",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			Fatalf("Please specify a key or key prefix to delete")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		client := setupKvstore(ctx, logging.DefaultSlogLogger)

		if recursive {
			if err := client.DeletePrefix(ctx, args[0]); err != nil {
				Fatalf("Unable to delete keys: %s", err)
			}
		} else {
			if err := client.Delete(ctx, args[0]); err != nil {
				Fatalf("Unable to delete key: %s", err)
			}
		}
	},
}

func init() {
	kvstoreCmd.AddCommand(kvstoreDeleteCmd)
	kvstoreDeleteCmd.Flags().BoolVar(&recursive, "recursive", false, "Recursive lookup")
}
