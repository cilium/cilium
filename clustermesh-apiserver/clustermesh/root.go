// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/hive"
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
