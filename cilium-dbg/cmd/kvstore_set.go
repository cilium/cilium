// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/kvstore"
)

var (
	key   string
	value string
)

var kvstoreSetCmd = &cobra.Command{
	Use:     "set [options] <key>",
	Short:   "Set a key and value",
	Example: "cilium kvstore set foo=bar",
	Run: func(cmd *cobra.Command, args []string) {
		if key == "" {
			Fatalf("--key attribute reqiured")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		setupKvstore(ctx)

		err := kvstore.Client().Set(ctx, key, []byte(value))
		if err != nil {
			Fatalf("Unable to set key: %s", err)
		}
	},
}

func init() {
	kvstoreCmd.AddCommand(kvstoreSetCmd)
	kvstoreSetCmd.Flags().StringVar(&key, "key", "", "Key")
	kvstoreSetCmd.Flags().StringVar(&value, "value", "", "Value")
}
