// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package certloader

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

// Cell creates the cell for certloader that provides a promise that resolves to
// a WatchedServerConfig. The config can be used to obtain a tls.Config which can
// transparently reload certificates between two connections. The promise resolves
// when the certificates become ready and have been loaded.
func Cell[Cfg cell.Flagger](cfg Cfg) cell.Cell {
	return cell.Module(
		"certloader",
		"Server TLS certificates loader",

		cell.Config(cfg),
		cell.Provide(newWatchedConfig),
	)
}

// Config contains the configuration for the certloader cell.
type Config struct {
	TLS              bool
	TLSCertFile      string
	TLSKeyFile       string
	TLSClientCAFiles []string
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("tls", def.TLS, "Enable TLS on the server.")
	flags.String("tls-cert-file", def.TLSCertFile, "Path to a TLS public certificate file. The file must contain PEM encoded data.")
	flags.String("tls-key-file", def.TLSKeyFile, "Path to a TLS private key file. The file must contain PEM encoded data.")
	flags.StringSlice("tls-client-ca-files", def.TLSClientCAFiles, strings.Join([]string{
		"Paths to one or more TLS public client CA certificates files to use for TLS with mutual authentication (mTLS).",
		"The files must contain PEM encoded data. When provided, this option effectively enables mTLS.",
	}, " "))
}

func newWatchedConfig(lc cell.Lifecycle, log *slog.Logger, cfg Config) (promise.Promise[*WatchedServerConfig], error) {
	if !cfg.TLS {
		return nil, nil
	}

	metricsTLSConfigChan, err := FutureWatchedServerConfig(
		log.With(logfields.Config, "hubble-metrics-server-tls"),
		cfg.TLSClientCAFiles, cfg.TLSCertFile, cfg.TLSKeyFile,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Hubble metrics server TLS configuration: %w", err)
	}

	resolver, promise := promise.New[*WatchedServerConfig]()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	lc.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() {
					log.Info("stopped in OnStop")
				}()
				waitingMsgTimeout := time.After(30 * time.Second)
				var metricsTLSConfig *WatchedServerConfig
				for metricsTLSConfig == nil {
					select {
					case metricsTLSConfig = <-metricsTLSConfigChan:
					case <-waitingMsgTimeout:
						log.Info("Waiting for Hubble metrics server TLS certificate and key files to be created")
					case <-ctx.Done():
						resolver.Reject(fmt.Errorf("timeout while waiting for Hubble metrics server TLS certificate and key files to be created: %w", ctx.Err()))
						return
					}
				}
				resolver.Resolve(metricsTLSConfig)
			}()
			return nil
		},
		OnStop: func(ctx cell.HookContext) error {
			cancel()
			wg.Wait()

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
