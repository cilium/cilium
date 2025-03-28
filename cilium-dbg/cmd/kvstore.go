// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"log/slog"
	"maps"

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

func setupKvstore(ctx context.Context, logger *slog.Logger) kvstore.BackendOperations {
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
			maps.Copy(kvStoreOpts, cfgStatus.KvstoreConfiguration.Options)
		}
	}

	client, errch := kvstore.NewClient(ctx, logger, kvStore, kvStoreOpts, nil)
	select {
	case <-ctx.Done():
		Fatalf("Unable to connect to the kvstore")
	case err, isErr := <-errch:
		if isErr {
			Fatalf("Unable to connect to the kvstore: %v", err)
		}
	}

	return client
}

func init() {
	RootCmd.AddCommand(kvstoreCmd)
	flags := kvstoreCmd.PersistentFlags()
	flags.StringVar(&kvStore, "kvstore", "", "Key-Value Store type")
	flags.Var(option.NewNamedMapOptions("kvstore-opts", &kvStoreOpts, nil), "kvstore-opt", "Key-Value Store options")
}
