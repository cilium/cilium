// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/clustermesh/kvstoremesh"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/version"
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

	Metrics     kvstoremesh.Metrics
	Shutdowner  hive.Shutdowner
	Log         *slog.Logger
	SyncWaiter  kvstoremesh.SyncWaiter
	KVStoreMesh *kvstoremesh.KVStoreMesh
}

func registerLeaderElectionHooks(lc cell.Lifecycle, llc *LeaderLifecycle, params params) {
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			wg.Add(1)
			go func() {
				runLeaderElection(ctx, llc, params)
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

func runLeaderElection(ctx context.Context, lc *LeaderLifecycle, params params) {

	params.Client.RegisterLockLeaseExpiredObserver(backendLockName, func(string) {
		params.Shutdowner.Shutdown(hive.ShutdownWithError(errors.New("Leader election lost")))
	})

	params.Metrics.LeaderElectionStatus.Set(float64(0))

	// Try to win leader election with short timeout to verify if we can
	// be immediately promoted as leader (e.g., we are the only replica).
	// If the timeout expires, just signal readiness and try again
	// with infinite timeout.
	params.Log.Info("Acquiring leader election lock")
	toCtx, cancel := context.WithTimeout(ctx, 10*time.Second)

	lock, err := params.Client.LockPath(toCtx, backendLockName)
	cancel()

	if err != nil && errors.Is(err, kvstore.ErrEtcdTimeout) {
		// signal readiness
		params.SyncWaiter.ForceReady()

		// try again with infinite timeout
		params.Log.Info("Reattempting to acquire leader election lock")
		lock, err = params.Client.LockPath(ctx, backendLockName)
	}

	if err != nil {
		params.Log.Error("Failed to acquire backend lock", logfields.Error, err)
		// no need to shutdown here as it is triggered by etcd lock lease expired hook
		return
	}

	defer func() {
		params.Log.Info("Releasing leader election lock")

		// unlock with timeout for case the etcd sidecar has already terminated
		toCtx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err = lock.Unlock(toCtx)
		if err != nil {
			params.Log.Error("Failed to release leader election lock", logfields.Error, err)
		}
	}()

	params.Log.Info("Leader election lock acquired")
	params.Metrics.LeaderElectionStatus.Set(float64(1))

	err = lc.Start(params.Log, ctx)
	if err != nil {
		params.Log.Error("Failed to run KvStoreMesh", logfields.Error, err)
		params.Shutdowner.Shutdown(hive.ShutdownWithError(err))
		return
	}

	<-ctx.Done()
}
