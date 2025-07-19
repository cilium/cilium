// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"context"
	"github.com/spf13/cobra"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/version"
	"github.com/cilium/hive/cell"
)

var (
	backendLockName = kvstore.BaseKeyPrefix + "/kvstoremesh-lock"
)

func NewCmd(h *hive.Hive) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "kvstoremesh",
		Short: "Run KVStoreMesh",
		Run: func(cmd *cobra.Command, args []string) {
			// slogloggercheck: it has been initialized in the PreRun function.
			if err := h.Run(logging.DefaultSlogLogger); err != nil {
				// slogloggercheck: log fatal errors using the default logger before it's initialized.
				logging.Fatal(logging.DefaultSlogLogger, err.Error())
			}
		},
		PreRun: func(cmd *cobra.Command, args []string) {
			// Overwrite the metrics namespace with the one specific for KVStoreMesh
			metrics.Namespace = metrics.CiliumKVStoreMeshNamespace
			option.Config.SetupLogging(h.Viper(), "kvstoremesh")

			// slogloggercheck: the logger has been initialized in the SetupLogging call above
			log := logging.DefaultSlogLogger.With(logfields.LogSubsys, "kvstoremesh")

			option.Config.Populate(log, h.Viper())
			option.LogRegisteredSlogOptions(h.Viper(), log)
			log.Info("Cilium KVStoreMesh", logfields.Version, version.Version)
		},
	}

	h.RegisterFlags(rootCmd.Flags())
	rootCmd.AddCommand(h.Command())

	return rootCmd
}

func registerKVStoreMeshHooks(log *slog.Logger, lc cell.Lifecycle, llc *LeaderLifecycle, client kvstore.Client, shutdowner hive.Shutdowner) {
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			wg.Add(1)
			go func() {
				runKVStoreMesh(ctx, log, llc, client, shutdowner)
				wg.Done()
			}()
			return nil
		},
		OnStop: func(ctx cell.HookContext) error {
			if err := llc.Stop(log, ctx); err != nil {
				return err
			}
			cancel()
			wg.Wait()
			return nil
		},
	})
}

func runKVStoreMesh(ctx context.Context, log *slog.Logger, lc *LeaderLifecycle, client kvstore.Client, shutdowner hive.Shutdowner) {
	client.RegisterLockLeaseExpiredObserver(backendLockName, func(string) {
		log.Error("Lost backend lock.")
		shutdowner.Shutdown()
	})

	for {
		log.Info("Locking backend")
		lock, err := client.LockPath(ctx, backendLockName)
		if err != nil {
			log.With("error", err).Warn("Failed to acquire backend lock")
			select {
			case <-ctx.Done():
				return
			case <-time.After(1 * time.Second):
				continue
			}
		}
		log.Info("Backend locked")

		lc.Start(log, ctx)

		<-ctx.Done()

		log.Info("Releasing backend lock")
		err = lock.Unlock(context.Background())
		if err != nil {
			log.With("error", err).Error("Failed to unlock backend lock")
		}
		return
	}
}
