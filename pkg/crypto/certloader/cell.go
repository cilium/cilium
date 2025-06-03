// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package certloader

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

// Config is the configuration for NewWatchedServerConfigPromise.
type Config struct {
	// Enable TLS watched server configuration.
	TLS bool
	// Path to a TLS public certificate file. The file must contain PEM encoded data.
	TLSCertFile string
	// Path to a TLS private key file. The file must contain PEM encoded data.
	TLSKeyFile string
	// Paths to one or more TLS public client CA certificates files to use for TLS with mutual
	// authentication (mTLS). The files must contain PEM encoded data. When provided, this option
	// effectively enables mTLS.
	TLSClientCAFiles []string
}

// NewWatchedServerConfigPromise provides a promise that resolves to a WatchedServerConfig.
// The resolved config can be used to obtain a tls.Config which can transparently reload
// certificates between two connections. The promise resolves when the certificates become
// ready and have been loaded.
//
// This is meant to be used as a Hive constructor and is recommended to be placed in a module
// and the promise provided wrapped in another type to avoid possible conflicts/replacements
// when used multiple times in the same hive.
func NewWatchedServerConfigPromise(lc cell.Lifecycle, jobGroup job.Group, log *slog.Logger, cfg Config) (promise.Promise[*WatchedServerConfig], error) {
	log = log.With(logfields.Config, "certloader-tls")
	if !cfg.TLS {
		log.Info("Certloader TLS watcher disabled")
		return nil, nil
	}

	resolver, promise := promise.New[*WatchedServerConfig]()

	jobGroup.Add(job.OneShot("certloader-tls", func(ctx context.Context, _ cell.Health) error {
		metricsTLSConfigChan, err := FutureWatchedServerConfig(
			ctx, log,
			cfg.TLSClientCAFiles, cfg.TLSCertFile, cfg.TLSKeyFile,
		)
		if err != nil {
			err := fmt.Errorf("failed to initialize certloader TLS configuration: %w", err)
			resolver.Reject(err)
			return err
		}

		waitingMsgTimeout := time.After(30 * time.Second)
		var metricsTLSConfig *WatchedServerConfig
		for metricsTLSConfig == nil {
			select {
			case metricsTLSConfig = <-metricsTLSConfigChan:
			case <-waitingMsgTimeout:
				log.Info("Waiting for certloader TLS certificate and key files to be created")
			case <-ctx.Done():
				return nil
			}
		}
		resolver.Resolve(metricsTLSConfig)
		return nil
	}))

	lc.Append(cell.Hook{
		OnStop: func(ctx cell.HookContext) error {
			// stop the resolved config watcher (best effort)
			ctx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			cfg, _ := promise.Await(ctx)
			if cfg != nil {
				cfg.Stop()
			}
			return nil
		},
	})

	return promise, nil
}
