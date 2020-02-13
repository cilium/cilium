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
