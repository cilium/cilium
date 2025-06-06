// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/pkg/kvstore"
)

// BackendFactoryFn is the type of the function to create the etcd client.
type BackendFactoryFn func(ctx context.Context, logger *slog.Logger,
	cfgpath string, extra kvstore.ExtraOptions) (kvstore.BackendOperations, chan error)

// DefaultBackendFactory returns the default BackendFactoryFn, configured with
// the parameters from the global kvstore configuration.
func DefaultBackendFactory(cfg kvstore.Config) BackendFactoryFn {
	return func(ctx context.Context, logger *slog.Logger, cfgpath string, extra kvstore.ExtraOptions) (kvstore.BackendOperations, chan error) {
		opts := map[string]string{
			kvstore.EtcdOptionConfig: cfgpath,
		}

		for key, value := range cfg.KVStoreOpt {
			switch key {
			case kvstore.EtcdRateLimitOption, kvstore.EtcdMaxInflightOption, kvstore.EtcdListLimitOption,
				kvstore.EtcdOptionKeepAliveHeartbeat, kvstore.EtcdOptionKeepAliveTimeout:
				opts[key] = value
			}
		}

		extra.LeaseTTL = cfg.KVStoreLeaseTTL
		extra.MaxConsecutiveQuorumErrors = cfg.KVstoreMaxConsecutiveQuorumErrors

		return kvstore.NewClient(ctx, logger, kvstore.EtcdBackendName, opts, extra)
	}
}
