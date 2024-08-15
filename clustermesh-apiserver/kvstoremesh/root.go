// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/version"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "kvstoremesh")
)

func NewCmd(h *hive.Hive) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "kvstoremesh",
		Short: "Run KVStoreMesh",
		Run: func(cmd *cobra.Command, args []string) {
			if err := h.Run(slog.Default()); err != nil {
				log.Fatal(err)
			}
		},
		PreRun: func(cmd *cobra.Command, args []string) {
			// Overwrite the metrics namespace with the one specific for KVStoreMesh
			metrics.Namespace = metrics.CiliumKVStoreMeshNamespace
			option.Config.Populate(h.Viper())
			if err := logging.SetupLogging(option.Config.LogDriver, option.Config.LogOpt, "kvstoremesh", option.Config.Debug); err != nil {
				log.Fatal(err)
			}
			option.LogRegisteredOptions(h.Viper(), log)
			log.Infof("Cilium KVStoreMesh %s", version.Version)
		},
	}

	h.RegisterFlags(rootCmd.Flags())
	rootCmd.AddCommand(h.Command())

	return rootCmd
}

func registerClusterInfoValidator(lc cell.Lifecycle, cinfo types.ClusterInfo, log logrus.FieldLogger) {
	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			if err := cinfo.InitClusterIDMax(); err != nil {
				return err
			}
			if err := cinfo.ValidateStrict(log); err != nil {
				return err
			}
			return nil
		},
	})
}
