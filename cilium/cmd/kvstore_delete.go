// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"time"

	"github.com/cilium/cilium/pkg/kvstore"

	"github.com/spf13/cobra"
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

		setupKvstore(ctx)

		if recursive {
			if err := kvstore.Client().DeletePrefix(ctx, args[0]); err != nil {
				Fatalf("Unable to delete keys: %s", err)
			}
		} else {
			if err := kvstore.Client().Delete(ctx, args[0]); err != nil {
				Fatalf("Unable to delete key: %s", err)
			}
		}
	},
}

func init() {
	kvstoreCmd.AddCommand(kvstoreDeleteCmd)
	kvstoreDeleteCmd.Flags().BoolVar(&recursive, "recursive", false, "Recursive lookup")
}
