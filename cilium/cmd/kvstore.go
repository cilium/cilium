// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/option"
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
	flags.StringVar(&kvStore, "kvstore", "", "Key-Value Store type")
	flags.Var(option.NewNamedMapOptions("kvstore-opts", &kvStoreOpts, nil), "kvstore-opt", "Key-Value Store options")
}
