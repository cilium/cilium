// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"context"
	"errors"
	"github.com/spf13/cobra"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/cilium/clustermesh-apiserver/syncstate"
	"github.com/cilium/cilium/pkg/clustermesh/kvstoremesh"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/version"
	"github.com/cilium/hive/cell"
	"github.com/prometheus/client_golang/prometheus"
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

type params struct {
	cell.In

	// Client is the client targeting the local cluster
	Client kvstore.Client

	Metrics    kvstoremesh.Metrics
	Shutdowner hive.Shutdowner
	Log        *slog.Logger
	SyncState  syncstate.SyncState
}

func registerLeaderElectionHooks(lc cell.Lifecycle, llc *LeaderLifecycle, params params) {
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			wg.Add(1)
			go func() {
				runLeaderElection(ctx, params.Log, llc, params.Client, params.Shutdowner, params.Metrics, params.SyncState)
				wg.Done()
			}()
			return nil
		},
		OnStop: func(hctx cell.HookContext) error {
			if err := llc.Stop(params.Log, hctx); err != nil {
				return err
			}
			cancel()
			wg.Wait()
			return nil
		},
	})
}

func runLeaderElection(ctx context.Context, log *slog.Logger, lc *LeaderLifecycle, client kvstore.Client, shutdowner hive.Shutdowner, kvMetrics kvstoremesh.Metrics, SyncState syncstate.SyncState) {

	syncedCallback := SyncState.WaitForResource()

	client.RegisterLockLeaseExpiredObserver(backendLockName, func(string) {
		shutdowner.Shutdown(hive.ShutdownWithError(errors.New("Leader election lost")))
	})

	kvMetrics.LeaderElectionStatus.With(prometheus.Labels{metrics.LabelLeaderElectionName: "kvstoremesh"}).Set(float64(0))

	log.Info("Acquiring leader election lock")
	toCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var lock kvstore.KVLocker
	lock, err := client.LockPath(toCtx, backendLockName)

	if err == nil {
		syncedCallback(ctx)
	} else {
		if err.Error() == "etcd client timeout exceeded" {
			syncedCallback(ctx)

			// try again with infinite timeout
			log.Info("Reattempting to acquire leader election lock")
			lock, err = client.LockPath(ctx, backendLockName)
		}
		if err != nil {
			log.With("error", err).Info("Failed to acquire backend lock")
			return
		}
	}
	log.Info("Leader election lock acquired")
	kvMetrics.LeaderElectionStatus.With(prometheus.Labels{metrics.LabelLeaderElectionName: "kvstoremesh"}).Set(float64(1))

	lc.Start(log, ctx)

	<-ctx.Done()

	log.Info("Releasing leader election lock")
	err = lock.Unlock(context.Background())
	if err != nil {
		log.With("error", err).Error("Failed to release leader election lock")
	}
}
