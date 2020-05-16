// Copyright 2018-2019 Authors of Cilium
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
	"fmt"
	"os"
	"time"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/kvstore"

	"github.com/spf13/cobra"
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
			if command.OutputJSON() {
				if err := command.PrintOutput(pairs); err != nil {
					os.Exit(1)
				}
				return
			}
			for k, v := range pairs {
				fmt.Printf("%s => %s\n", k, string(v.Data))
			}
		} else {
			val, err := kvstore.Client().Get(ctx, key)
			if err != nil {
				Fatalf("Unable to retrieve key %s: %s", key, err)
			}
			if val == nil {
				Fatalf("key %s is not found", key)
			}
			if command.OutputJSON() {
				if err := command.PrintOutput(string(val)); err != nil {
					os.Exit(1)
				}
				return
			}
			fmt.Printf("%s => %s\n", key, string(val))
		}
	},
}

func init() {
	kvstoreCmd.AddCommand(kvstoreGetCmd)
	kvstoreGetCmd.Flags().BoolVar(&recursive, "recursive", false, "Recursive lookup")
	command.AddJSONOutput(kvstoreGetCmd)
}
