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

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/option"

	"github.com/spf13/cobra"
)

var (
	recursive   bool
	kvStore     string
	kvStoreOpts = make(map[string]string)
)

// kvstoreCmd represents the bpf command
var kvstoreCmd = &cobra.Command{
	Use:   "kvstore",
	Short: "Direct access to the kvstore",
}

func setupKvstore(ctx context.Context) {
	if kvStore == "" || len(kvStoreOpts) == 0 {
		resp, err := client.ConfigGet()
		if err != nil {
			Fatalf("Unable to retrieve cilium configuration: %s", err)
		}
		if resp.Status == nil {
			Fatalf("Unable to retrieve cilium configuration: empty response")
		}

		cfgStatus := resp.Status

		if kvStore == "" {
			kvStore = cfgStatus.KvstoreConfiguration.Type
		}

		if len(kvStoreOpts) == 0 {
			for k, v := range cfgStatus.KvstoreConfiguration.Options {
				kvStoreOpts[k] = v
			}
		}
	}

	if err := kvstore.Setup(ctx, kvStore, kvStoreOpts, nil); err != nil {
		Fatalf("Unable to setup kvstore: %s", err)
	}
}

func init() {
	rootCmd.AddCommand(kvstoreCmd)
	flags := kvstoreCmd.PersistentFlags()
	flags.StringVar(&kvStore, "kvstore", "", "kvstore type")
	flags.Var(option.NewNamedMapOptions("kvstore-opts", &kvStoreOpts, nil), "kvstore-opt", "kvstore options")
}
