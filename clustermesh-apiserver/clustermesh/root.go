// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/clustermesh/operator"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	cmutils "github.com/cilium/cilium/pkg/clustermesh/utils"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/version"
)

func NewCmd(h *hive.Hive) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "clustermesh",
		Short: "Run ClusterMesh",
		Run: func(cmd *cobra.Command, args []string) {
			// slogloggercheck: it has been initialized in the PreRun function.
			if err := h.Run(logging.DefaultSlogLogger); err != nil {
				// slogloggercheck: log fatal errors using the default logger before it's initialized.
				logging.Fatal(logging.DefaultSlogLogger, err.Error())
			}
		},
		PreRun: func(cmd *cobra.Command, args []string) {
			// Overwrite the metrics namespace with the one specific for the ClusterMesh API Server
			metrics.Namespace = metrics.CiliumClusterMeshAPIServerNamespace
			option.Config.SetupLogging(h.Viper(), "clustermesh-apiserver")

			// slogloggercheck: it has been properly initialized now.
			logger := logging.DefaultSlogLogger.With(logfields.LogSubsys, "clustermesh-apiserver")

			option.Config.Populate(logger, h.Viper())
			option.LogRegisteredSlogOptions(h.Viper(), logger)
			logger.Info("Cilium ClusterMesh", logfields.Version, version.Version)
		},
	}

	h.RegisterFlags(rootCmd.Flags())
	rootCmd.AddCommand(h.Command())
	return rootCmd
}

type parameters struct {
	cell.In

	CfgMCSAPI   operator.MCSAPIConfig
	ClusterInfo cmtypes.ClusterInfo
	Backend     kvstore.Client

	Logger *slog.Logger
}

func RegisterHooks(lc cell.Lifecycle, params parameters) error {
	lc.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			startServer(params.ClusterInfo, params.Backend, params.CfgMCSAPI.ClusterMeshEnableMCSAPI, params.Logger)
			return nil
		},
	})
	return nil
}

func startServer(
	cinfo cmtypes.ClusterInfo,
	backend kvstore.BackendOperations,
	clusterMeshEnableMCSAPI bool,
	logger *slog.Logger,
) {
	logger.Info(
		"Starting clustermesh-apiserver...",
		logfields.ClusterName, cinfo.Name,
		logfields.ClusterID, cinfo.ID,
	)

	config := cmtypes.CiliumClusterConfig{
		ID: cinfo.ID,
		Capabilities: cmtypes.CiliumClusterConfigCapabilities{
			SyncedCanaries:        true,
			MaxConnectedClusters:  cinfo.MaxConnectedClusters,
			ServiceExportsEnabled: &clusterMeshEnableMCSAPI,
		},
	}

	_, err := cmutils.EnforceClusterConfig(context.Background(), cinfo.Name, config, backend, logger)
	if err != nil {
		logging.Fatal(logger, "Unable to set local cluster config on kvstore", logfields.Error, err)
	}

	logger.Info("Initialization complete")
}
