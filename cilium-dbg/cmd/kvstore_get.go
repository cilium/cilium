// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/kvstore"
)

var kvstoreGetCmd = &cobra.Command{
	Use:     "get [options] <key>",
	Short:   "Retrieve a key",
	Example: "cilium kvstore get --recursive foo",
	Run: func(cmd *cobra.Command, args []string) {
		key := ""

		if len(args) > 0 {
			key = args[0]
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		setupKvstore(ctx)

		if recursive {
			pairs, err := kvstore.Client().ListPrefix(ctx, key)
			if err != nil {
				Fatalf("Unable to list keys: %s", err)
			}
			if command.OutputOption() {
				if err := command.PrintOutput(pairs); err != nil {
					os.Exit(1)
				}
				return
			}
			for k, v := range pairs {
				fmt.Printf("%s => %s\n", k, v.Data)
			}
		} else {
			val, err := kvstore.Client().Get(ctx, key)
			if err != nil {
				Fatalf("Unable to retrieve key %s: %s", key, err)
			}
			if val == nil {
				Fatalf("key %s is not found", key)
			}
			if command.OutputOption() {
				if err := command.PrintOutput(string(val)); err != nil {
					os.Exit(1)
				}
				return
			}
			fmt.Printf("%s => %s\n", key, val)
		}
	},
}

func init() {
	kvstoreCmd.AddCommand(kvstoreGetCmd)
	kvstoreGetCmd.Flags().BoolVar(&recursive, "recursive", false, "Recursive lookup")
	command.AddOutputOption(kvstoreGetCmd)
}
